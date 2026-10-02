//! `#[world_test]`: integration tests from a declared world and a body.
//!
//! ```ignore
//! /// Docs and other attributes pass through to the test.
//! #[world_test(
//!     backend = BitcoindBackend,
//!     maker_behaviors = [Normal, CloseAtContractSigsForRecvr],
//!     takers = [Normal],
//!     setup = [
//!         fund_taker_default(3) as baseline,
//!         fund_makers_default(),
//!         start_makers(120),
//!         mine(1),
//!     ],
//!     swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
//! )]
//! fn maker_abort3_case2(world: &mut World, baseline: Amount, params: SwapParams) {
//!     // the scenario
//! }
//! ```
//!
//! expands to
//!
//! ```ignore
//! /// Docs and other attributes pass through to the test.
//! #[test]
//! fn maker_abort3_case2() {
//!     fn maker_abort3_case2(world: &mut World, baseline: Amount, params: SwapParams) {
//!         // the scenario
//!     }
//!     let mut world = crate::test_framework::World::builder::<BitcoindBackend>()
//!         .makers(2)
//!         .maker_behaviors({ use ::openswap::maker::MakerBehavior::*; [Normal, CloseAtContractSigsForRecvr] })
//!         .takers({ use ::openswap::taker::TakerBehavior::*; [Normal] })
//!         .build();
//!     ::log::warn!("{}", "Running Test: maker_abort3_case2 - Docs and other ...");
//!     let baseline = world.fund_taker_default(3);
//!     world.fund_makers_default();
//!     world.start_makers(120);
//!     world.mine(1);
//!     let params = ::openswap::taker::SwapParams::new(ProtocolVersion::Legacy,
//!         Amount::from_sat(500_000), 2).with_tx_count(3);
//!     maker_abort3_case2(&mut world, baseline, params);
//!     world.finish();
//! }
//! ```
//!
//! - `backend` is required, unless every case names its own. Every other
//!   key except `setup`, `swap` and `cases` is the `WorldBuilder` method of
//!   the same name: `key = value` calls `.key(value)`, a bare `key` calls
//!   `.key()`. Nothing is defaulted, except that `makers` is the length of a
//!   `maker_behaviors` list when omitted.
//! - `maker_behaviors` and `takers` see the `MakerBehavior` and
//!   `TakerBehavior` variants unqualified.
//! - `setup` lists `World` steps run in order after `build()`. `step(..) as x`
//!   binds the step's result to the body parameter named `x`.
//! - `swap(protocol, sats, makers[, tx_count][, confirms])` builds the
//!   `SwapParams` passed to the body parameter `params`. Unset `tx_count` and
//!   `confirms` keep `SwapParams::new`'s defaults (2 and 1). `protocol` is
//!   `Legacy`, `Taproot` or any `ProtocolVersion` expression, and every value
//!   may name a case argument.
//! - The body's first parameter receives the world; every later parameter
//!   is a setup binding, `params` or a case argument, matched by name. A body
//!   with one type parameter (`fn body<B: TestBackend>(..)`) receives the
//!   test's backend type through it.
//! - Once the world is built, the test logs `Running Test: <name> - <first
//!   doc line>`, so the body needs no `warn!("Running Test: ...")` of its own.
//!
//! Without `cases` the test is named after the body. With
//! `cases = [test_name(arg = value, ..), ...]` the body stays a plain fn and
//! every case is a `#[test]` of that name. Every case names the same
//! arguments; they are bound as locals before `build()`, so keys can use them
//! (`takers = [behavior]`), and the body takes the ones it needs by name. A
//! case's own `///` docs and attributes go to its test; the body's non-doc
//! attributes go to every case. `backend = ElectrumBackend` in a case is not
//! a local: it builds that case's world on its own backend.

use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::Parser, punctuated::Punctuated, spanned::Spanned, Attribute, Error, Expr, ExprCall,
    FnArg, Ident, ItemFn, Meta, MetaList, MetaNameValue, Pat, Result, Token, Type, TypePath,
};

/// Turns a scenario body into `#[test]`s that build its world, run its setup
/// steps, call the body and finish the world. See the crate docs.
#[proc_macro_attribute]
pub fn world_test(args: TokenStream, item: TokenStream) -> TokenStream {
    expand(args.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// One `setup` entry: `world.<call>`, optionally bound to a name.
struct Step {
    binding: Option<Ident>,
    call: TokenStream2,
}

/// One `cases` row: its test's name, attributes, backend and named arguments.
struct Case {
    attrs: Vec<Attribute>,
    name: Ident,
    backend: Option<Type>,
    args: Vec<(Ident, Expr)>,
}

fn expand(args: TokenStream2, item: TokenStream2) -> Result<TokenStream2> {
    let metas = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(args)?;
    let mut body: ItemFn = syn::parse2(item)?;
    // Mixed-site: test code cannot name, and so cannot shadow, the world.
    let world = Ident::new("world", Span::mixed_site());
    let params = Ident::new("params", Span::call_site());

    let mut seen = HashSet::new();
    let mut backend = None;
    let mut steps = Vec::new();
    let mut swap = None;
    let mut cases = None;
    let mut builder_calls = Vec::new();
    let mut maker_count = None;
    let mut makers_given = false;
    for meta in metas {
        let key = meta.path().require_ident()?.clone();
        if !seen.insert(key.to_string()) {
            return Err(Error::new(key.span(), format!("`{key}` is given twice")));
        }
        let value = match meta {
            Meta::Path(_) => {
                builder_calls.push(quote!(.#key()));
                continue;
            }
            Meta::NameValue(nv) => nv.value,
            Meta::List(list) if key == "swap" => {
                swap = Some(swap_params(&list)?);
                continue;
            }
            Meta::List(list) => {
                return Err(Error::new(
                    list.span(),
                    "expected `key = value` or a bare `key`",
                ))
            }
        };
        match key.to_string().as_str() {
            "backend" => backend = Some(backend_type(value)?),
            "setup" => steps = setup_steps(value, &world)?,
            "cases" => cases = Some(case_rows(value)?),
            "swap" => {
                return Err(Error::new(
                    key.span(),
                    "write `swap(protocol = .., sats = .., makers = ..)`",
                ))
            }
            "maker_behaviors" => {
                if let Expr::Array(list) = &value {
                    maker_count = Some(list.elems.len());
                }
                builder_calls.push(quote! {
                    .#key({
                        #[allow(unused_imports)]
                        use ::openswap::maker::MakerBehavior::*;
                        #value
                    })
                });
            }
            "takers" => builder_calls.push(quote! {
                .#key({
                    #[allow(unused_imports)]
                    use ::openswap::taker::TakerBehavior::*;
                    #value
                })
            }),
            "makers" => {
                makers_given = true;
                builder_calls.push(quote!(.#key(#value)));
            }
            _ => builder_calls.push(quote!(.#key(#value))),
        }
    }
    // A case's own `backend` overrides the shared one; every test needs one.
    let every_case_has_backend = cases
        .as_deref()
        .is_some_and(|cases: &[Case]| cases.iter().all(|case| case.backend.is_some()));
    if backend.is_none() && !every_case_has_backend {
        return Err(Error::new(
            Span::call_site(),
            "`backend = ...` is required, e.g. `backend = BitcoindBackend`, \
             unless every case gives its own",
        ));
    }
    if let (false, Some(count)) = (makers_given, maker_count) {
        builder_calls.insert(0, quote!(.makers(#count)));
    }

    if let Some(test) = body.attrs.iter().find(|attr| attr.path().is_ident("test")) {
        return Err(Error::new(
            test.span(),
            "#[world_test] adds #[test] itself; remove this one",
        ));
    }
    // A body may take one type parameter: the test's backend.
    let generics = &body.sig.generics.params;
    let takes_backend = match generics.first() {
        None => false,
        Some(syn::GenericParam::Type(_)) if generics.len() == 1 => true,
        Some(_) => {
            return Err(Error::new(
                generics.span(),
                "a #[world_test] body takes at most one type parameter, the backend",
            ))
        }
    };
    if body.sig.asyncness.is_some() {
        return Err(Error::new(
            body.sig.span(),
            "a #[world_test] body is not async",
        ));
    }

    // The first parameter takes the world; the rest are bindings or case args.
    let mut inputs = body.sig.inputs.iter();
    if inputs.next().is_none() {
        return Err(Error::new(
            body.sig.span(),
            "the body takes the world first, e.g. `world: &mut World`",
        ));
    }
    let mut bound: HashSet<String> = steps
        .iter()
        .filter_map(|step| step.binding.as_ref().map(Ident::to_string))
        .collect();
    if swap.is_some() {
        bound.insert(params.to_string());
    }
    // Every case names the same arguments; they bind like setup results.
    let case_names: Vec<String> = match cases.as_deref() {
        Some([first, rest @ ..]) => {
            let names: Vec<String> = first.args.iter().map(|(n, _)| n.to_string()).collect();
            for case in rest {
                let mut theirs: Vec<String> =
                    case.args.iter().map(|(n, _)| n.to_string()).collect();
                let mut ours = names.clone();
                theirs.sort();
                ours.sort();
                if theirs != ours {
                    return Err(Error::new(
                        case.name.span(),
                        format!("every case names the same arguments: {}", names.join(", ")),
                    ));
                }
            }
            names
        }
        Some([]) => return Err(Error::new(Span::call_site(), "`cases` is empty")),
        None => Vec::new(),
    };
    bound.extend(case_names.iter().cloned());
    let mut call_args = Vec::new();
    for input in inputs {
        let name = match input {
            FnArg::Typed(typed) => match &*typed.pat {
                Pat::Ident(pat) => pat.ident.clone(),
                other => return Err(Error::new(other.span(), "expected a parameter name")),
            },
            FnArg::Receiver(receiver) => {
                return Err(Error::new(receiver.span(), "a body cannot take `self`"))
            }
        };
        if !bound.contains(&name.to_string()) {
            return Err(Error::new(
                name.span(),
                format!(
                    "nothing binds `{name}`: add `... as {name}` to `setup`, \
                     `swap(..)` for `params`, or `{name} = ..` to every case"
                ),
            ));
        }
        call_args.push(name);
    }

    let step_stmts: Vec<_> = steps
        .iter()
        .map(|step| {
            let call = &step.call;
            match &step.binding {
                Some(binding) => quote!(let #binding = #call;),
                None => quote!(#call;),
            }
        })
        .collect();
    let swap_stmt = swap.map(|swap| quote!(let #params = #swap;));
    let run = |name: &Ident,
               summary: &[Attribute],
               backend: &Type,
               locals: TokenStream2,
               call: TokenStream2| {
        let running = running_line(name, summary);
        let call = if takes_backend {
            quote!(#call::<#backend>)
        } else {
            call
        };
        quote! {
            #locals
            let mut #world = crate::test_framework::World::builder::<#backend>()
                #(#builder_calls)*
                .build();
            // After build: the framework sets the logger up.
            ::log::warn!("{}", #running);
            #(#step_stmts)*
            #swap_stmt
            #call(&mut #world, #(#call_args),*);
            #world.finish();
        }
    };

    let Some(cases) = cases else {
        let attrs = std::mem::take(&mut body.attrs);
        body.vis = syn::Visibility::Inherited;
        let name = body.sig.ident.clone();
        let backend = backend.expect("checked above");
        let test_body = run(&name, &attrs, &backend, quote!(), quote!(#name));
        return Ok(quote! {
            #(#attrs)*
            #[test]
            fn #name() {
                #body
                #test_body
            }
        });
    };

    // Docs stay on the shared body; every other attribute goes to each case,
    // and a `cfg` also stays on the body so both compile out together.
    let body_name = body.sig.ident.clone();
    let (docs, shared): (Vec<_>, Vec<_>) = std::mem::take(&mut body.attrs)
        .into_iter()
        .partition(|attr| attr.path().is_ident("doc"));
    body.attrs = docs.clone();
    body.attrs.extend(
        shared
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"))
            .cloned(),
    );
    let mut tests = Vec::new();
    for case in cases {
        if case.name == body_name {
            return Err(Error::new(
                case.name.span(),
                "a case needs a name of its own; the body keeps its name",
            ));
        }
        let locals = case
            .args
            .iter()
            .map(|(name, value)| quote!(let #name = #value;));
        let locals = quote!(#(#locals)*);
        let summary = if case.attrs.iter().any(|attr| attr.path().is_ident("doc")) {
            &case.attrs
        } else {
            &docs
        };
        let backend = case.backend.as_ref().or(backend.as_ref());
        let backend = backend.expect("checked above");
        let test_body = run(&case.name, summary, backend, locals, quote!(#body_name));
        let (case_attrs, name) = (&case.attrs, &case.name);
        tests.push(quote! {
            #(#case_attrs)*
            #(#shared)*
            #[test]
            fn #name() {
                #test_body
            }
        });
    }
    Ok(quote! {
        #body
        #(#tests)*
    })
}

/// `Running Test: <name> - <first doc line>`, or just the name without docs.
/// Logs stay ASCII, so the doc line's typographic punctuation is spelled out.
fn running_line(name: &Ident, attrs: &[Attribute]) -> String {
    let summary = attrs.iter().find_map(|attr| match &attr.meta {
        Meta::NameValue(nv) if nv.path.is_ident("doc") => match &nv.value {
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(doc),
                ..
            }) => Some(ascii(doc.value().trim())),
            _ => None,
        },
        _ => None,
    });
    match summary {
        Some(summary) if !summary.is_empty() => format!("Running Test: {name} - {summary}"),
        _ => format!("Running Test: {name}"),
    }
}

/// `text` with dashes, quotes and arrows in ASCII; any other non-ASCII is dropped.
fn ascii(text: &str) -> String {
    text.chars()
        .filter_map(|c| match c {
            '\u{2013}' | '\u{2014}' => Some("-".to_string()),
            '\u{2018}' | '\u{2019}' => Some("'".to_string()),
            '\u{201c}' | '\u{201d}' => Some("\"".to_string()),
            '\u{2192}' => Some("->".to_string()),
            '\u{2026}' => Some("...".to_string()),
            c if c.is_ascii() => Some(c.to_string()),
            _ => None,
        })
        .collect()
}

/// `backend = BitcoindBackend` arrives as a path expression; read it as a type.
fn backend_type(value: Expr) -> Result<Type> {
    match value {
        Expr::Path(path) if path.qself.is_none() => Ok(Type::Path(TypePath {
            qself: None,
            path: path.path,
        })),
        other => Err(Error::new(
            other.span(),
            "expected a backend type, e.g. `BitcoindBackend`",
        )),
    }
}

/// `swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3)`.
fn swap_params(list: &MetaList) -> Result<TokenStream2> {
    let fields = list.parse_args_with(Punctuated::<MetaNameValue, Token![,]>::parse_terminated)?;
    let (mut protocol, mut sats, mut makers, mut calls) = (None, None, None, Vec::new());
    let mut seen = HashSet::new();
    for field in fields {
        let key = field.path.require_ident()?.clone();
        if !seen.insert(key.to_string()) {
            return Err(Error::new(key.span(), format!("`{key}` is given twice")));
        }
        let value = field.value;
        match key.to_string().as_str() {
            // A bare variant name is qualified; anything else, such as a case
            // argument, is a `ProtocolVersion` expression already.
            "protocol" => match &value {
                Expr::Path(path)
                    if path.path.is_ident("Legacy") || path.path.is_ident("Taproot") =>
                {
                    protocol = Some(quote! {
                        ::openswap::protocol::common_messages::ProtocolVersion::#path
                    });
                }
                other => protocol = Some(quote!(#other)),
            },
            "sats" => sats = Some(quote!(::bitcoin::Amount::from_sat(#value))),
            "makers" => makers = Some(quote!(#value)),
            "tx_count" => calls.push(quote!(.with_tx_count(#value))),
            "confirms" => calls.push(quote!(.with_required_confirms(#value))),
            _ => {
                return Err(Error::new(
                    key.span(),
                    "swap takes protocol, sats, makers, tx_count and confirms",
                ))
            }
        }
    }
    let missing = |what: &str| Error::new(list.span(), format!("swap(..) needs `{what}`"));
    let protocol = protocol.ok_or_else(|| missing("protocol"))?;
    let sats = sats.ok_or_else(|| missing("sats"))?;
    let makers = makers.ok_or_else(|| missing("makers"))?;
    Ok(quote! {
        ::openswap::taker::SwapParams::new(#protocol, #sats, #makers) #(#calls)*
    })
}

/// `setup = [step(args) as name, step(args), ...]`, each a `World` method.
fn setup_steps(value: Expr, world: &Ident) -> Result<Vec<Step>> {
    let Expr::Array(list) = value else {
        return Err(Error::new(
            value.span(),
            "expected `setup = [step(..), step(..) as name, ...]`",
        ));
    };
    list.elems
        .into_iter()
        .map(|elem| {
            let (call, binding) = match elem {
                Expr::Cast(cast) => {
                    let binding = match &*cast.ty {
                        Type::Path(path) if path.qself.is_none() => {
                            path.path.require_ident()?.clone()
                        }
                        other => {
                            return Err(Error::new(other.span(), "bind a step with `as name`"))
                        }
                    };
                    (*cast.expr, Some(binding))
                }
                other => (other, None),
            };
            let Expr::Call(call) = call else {
                return Err(Error::new(
                    call.span(),
                    "a setup step is a `World` method call, e.g. `mine(1)`",
                ));
            };
            let Expr::Path(method) = &*call.func else {
                return Err(Error::new(
                    call.func.span(),
                    "expected a `World` method name",
                ));
            };
            let method = method.path.require_ident()?;
            let args = &call.args;
            Ok(Step {
                binding,
                call: quote!(#world.#method(#args)),
            })
        })
        .collect()
}

/// `cases = [/// docs \n test_name(arg = value, ...), ...]`.
fn case_rows(value: Expr) -> Result<Vec<Case>> {
    let Expr::Array(list) = value else {
        return Err(Error::new(
            value.span(),
            "expected `cases = [test_name(args), ...]`",
        ));
    };
    list.elems
        .into_iter()
        .map(|elem| {
            let Expr::Call(ExprCall {
                attrs, func, args, ..
            }) = elem
            else {
                return Err(Error::new(
                    elem.span(),
                    "a case is `test_name(args)`, e.g. `rejects_x(Normal, \"needle\")`",
                ));
            };
            let Expr::Path(path) = &*func else {
                return Err(Error::new(func.span(), "expected the case's test name"));
            };
            let mut backend = None;
            let mut named = Vec::new();
            for arg in args {
                let Expr::Assign(assign) = arg else {
                    return Err(Error::new(arg.span(), "case arguments are `name = value`"));
                };
                let Expr::Path(name) = *assign.left else {
                    return Err(Error::new(assign.left.span(), "expected `name = value`"));
                };
                let name = name.path.require_ident()?.clone();
                // `backend` picks the row's builder type; it is not a local.
                if name == "backend" {
                    backend = Some(backend_type(*assign.right)?);
                } else {
                    named.push((name, *assign.right));
                }
            }
            Ok(Case {
                attrs,
                name: path.path.require_ident()?.clone(),
                backend,
                args: named,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::expand;
    use quote::quote;

    fn expand_err(args: proc_macro2::TokenStream, item: proc_macro2::TokenStream) -> String {
        match expand(args, item) {
            Ok(tokens) => panic!("expected an error, got {tokens}"),
            Err(err) => err.to_string(),
        }
    }

    #[test]
    fn expands_builder_steps_body_and_finish_in_order() {
        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                maker_behaviors = [Normal, CloseAtHashPreimage],
                takers = [Normal],
                check_blocklist,
                setup = [fund_taker_default(3) as baseline, mine(1)],
            ),
            quote!(
                /// Docs.
                #[ignore]
                fn scenario(world: &mut World, baseline: Amount) {}
            ),
        )
        .unwrap()
        .to_string();
        let order = [
            "# [doc",
            "# [ignore]",
            "# [test] fn scenario ()",
            "fn scenario (world : & mut World , baseline : Amount)",
            ":: < BitcoindBackend > ()",
            ". makers (2usize)",
            ". maker_behaviors",
            ". takers",
            ". check_blocklist ()",
            ". build ()",
            "\"Running Test: scenario - Docs.\"",
            "let baseline = world . fund_taker_default (3)",
            "world . mine (1)",
            "scenario (& mut world , baseline)",
            "world . finish ()",
        ];
        let mut rest = tokens.as_str();
        for piece in order {
            let at = rest
                .find(piece)
                .unwrap_or_else(|| panic!("`{piece}` missing or out of order in {tokens}"));
            rest = &rest[at + piece.len()..];
        }
    }

    #[test]
    fn explicit_makers_is_not_derived() {
        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                makers = 3,
                maker_behaviors = [Normal]
            ),
            quote!(
                fn scenario(world: &mut World) {}
            ),
        )
        .unwrap()
        .to_string();
        assert!(tokens.contains(". makers (3)"));
        assert!(!tokens.contains("1usize"));
    }

    #[test]
    fn refuses_malformed_declarations() {
        let body = quote!(
            fn scenario(world: &mut World) {}
        );
        let cases = [
            (
                quote!(takers = [Normal]),
                body.clone(),
                "`backend = ...` is required",
            ),
            (
                quote!(backend = BitcoindBackend),
                quote!(
                    fn scenario(world: &mut World, baseline: Amount) {}
                ),
                "nothing binds `baseline`",
            ),
            (
                quote!(backend = BitcoindBackend),
                quote!(
                    #[test]
                    fn scenario(world: &mut World) {}
                ),
                "adds #[test] itself",
            ),
            (
                quote!(
                    backend = BitcoindBackend,
                    takers = [Normal],
                    takers = [Normal]
                ),
                body.clone(),
                "`takers` is given twice",
            ),
            (
                quote!(backend = BitcoindBackend, setup = [world.mine(1)]),
                body.clone(),
                "a setup step is a `World` method call",
            ),
            (
                quote!(backend = BitcoindBackend),
                quote!(
                    fn scenario() {}
                ),
                "the body takes the world first",
            ),
        ];
        for (args, item, expected) in cases {
            let err = expand_err(args, item);
            assert!(err.contains(expected), "`{err}` lacks `{expected}`");
        }
    }

    #[test]
    fn swap_builds_the_params_binding() {
        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
            ),
            quote!(
                fn scenario(world: &mut World, params: SwapParams) {}
            ),
        )
        .unwrap()
        .to_string();
        for piece in [
            "let params = :: openswap :: taker :: SwapParams :: new",
            "ProtocolVersion :: Taproot",
            ":: bitcoin :: Amount :: from_sat (500_000)",
            ", 2)",
            ". with_tx_count (3)",
            "scenario (& mut world , params)",
        ] {
            assert!(tokens.contains(piece), "`{piece}` missing in {tokens}");
        }
        assert!(!tokens.contains("with_required_confirms"));

        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                swap(
                    protocol = protocol,
                    sats = 1,
                    makers = 1,
                    tx_count = tx_count
                ),
                cases = [a(protocol = ProtocolVersion::Legacy, tx_count = 2)],
            ),
            quote!(
                fn scenario(world: &mut World, params: SwapParams) {}
            ),
        )
        .unwrap()
        .to_string();
        assert!(tokens.contains("SwapParams :: new (protocol ,"), "{tokens}");
        assert!(tokens.contains(". with_tx_count (tx_count)"), "{tokens}");
    }

    #[test]
    fn cases_make_one_test_each_and_bind_their_arguments() {
        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                takers = [behavior],
                cases = [
                    /// First.
                    rejects_a(behavior = Normal, needle = "a"),
                    rejects_b(needle = "b", behavior = Normal),
                ],
            ),
            quote!(
                /// Shared.
                #[ignore]
                fn run_guard(world: &mut World, needle: &str) {}
            ),
        )
        .unwrap()
        .to_string();
        assert!(
            tokens.starts_with("# [doc = r\" Shared.\"] fn run_guard"),
            "{tokens}"
        );
        for (test, running) in [
            ("rejects_a", "Running Test: rejects_a - First."),
            ("rejects_b", "Running Test: rejects_b - Shared."),
        ] {
            let at = tokens
                .find(&format!("# [test] fn {test} ()"))
                .unwrap_or_else(|| panic!("no test {test} in {tokens}"));
            let test_tokens = &tokens[at..];
            let next = test_tokens[1..]
                .find("# [test]")
                .map_or(test_tokens.len(), |n| n + 1);
            let test_tokens = &test_tokens[..next];
            assert!(
                test_tokens.contains("let behavior = Normal"),
                "{test_tokens}"
            );
            assert!(test_tokens.contains(running), "{test_tokens}");
            assert!(
                test_tokens.contains("run_guard (& mut world , needle)"),
                "{test_tokens}"
            );
        }
        assert_eq!(tokens.matches("# [ignore]").count(), 2, "{tokens}");
    }

    #[test]
    fn refuses_malformed_cases_and_swap() {
        let body = quote!(
            fn run_guard(world: &mut World, needle: &str) {}
        );
        let cases = [
            (
                quote!(
                    backend = BitcoindBackend,
                    cases = [a(needle = "x"), b(other = "y")]
                ),
                "every case names the same arguments",
            ),
            (
                quote!(backend = BitcoindBackend, cases = [run_guard(needle = "x")]),
                "a case needs a name of its own",
            ),
            (
                quote!(backend = BitcoindBackend, cases = [a("x")]),
                "case arguments are `name = value`",
            ),
            (
                quote!(
                    backend = BitcoindBackend,
                    swap(sats = 1, makers = 1),
                    cases = [a(needle = "x")]
                ),
                "swap(..) needs `protocol`",
            ),
        ];
        for (args, expected) in cases {
            let err = expand_err(args, body.clone());
            assert!(err.contains(expected), "`{err}` lacks `{expected}`");
        }
    }

    #[test]
    fn a_case_backend_builds_its_world_and_reaches_a_generic_body() {
        let tokens = expand(
            quote!(
                backend = BitcoindBackend,
                cases = [
                    on_bitcoind(n = 1),
                    on_electrum(backend = ElectrumBackend, n = 2),
                ],
            ),
            quote!(
                fn run<B: TestBackend>(world: &mut World, n: u32) {}
            ),
        )
        .unwrap()
        .to_string();
        let electrum = tokens.find("fn on_electrum").expect("on_electrum test");
        let (bitcoind, electrum) = tokens.split_at(electrum);
        for (test, backend) in [(bitcoind, "BitcoindBackend"), (electrum, "ElectrumBackend")] {
            assert!(
                test.contains(&format!("World :: builder :: < {backend} >")),
                "{test}"
            );
            assert!(
                test.contains(&format!("run :: < {backend} > (& mut world")),
                "{test}"
            );
        }
        assert!(!electrum.contains("let backend"), "{electrum}");

        // Without a shared backend, every case must bring one.
        let err = expand_err(
            quote!(cases = [a(backend = ElectrumBackend, n = 1), b(n = 2)]),
            quote!(
                fn run(world: &mut World, n: u32) {}
            ),
        );
        assert!(err.contains("unless every case gives its own"), "{err}");
    }

    #[test]
    fn the_running_line_is_ascii() {
        let tokens = expand(
            quote!(backend = BitcoindBackend),
            quote!(
                /// Guards run in order — count, sum → duplicates, “x”.
                fn scenario(world: &mut World) {}
            ),
        )
        .unwrap()
        .to_string();
        assert!(
            tokens.contains(
                r#"Running Test: scenario - Guards run in order - count, sum -> duplicates, \"x\"."#
            ),
            "{tokens}"
        );
    }
}
