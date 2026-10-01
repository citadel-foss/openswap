//! `#[world_test]`: one integration test from a declared world and a body.
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
//! )]
//! fn maker_abort3_case2(world: &mut World, baseline: Amount) {
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
//!     fn maker_abort3_case2(world: &mut World, baseline: Amount) {
//!         // the scenario
//!     }
//!     let mut world = crate::test_framework::World::builder::<BitcoindBackend>()
//!         .makers(2)
//!         .maker_behaviors({ use ::openswap::maker::MakerBehavior::*; [Normal, CloseAtContractSigsForRecvr] })
//!         .takers({ use ::openswap::taker::TakerBehavior::*; [Normal] })
//!         .build();
//!     let baseline = world.fund_taker_default(3);
//!     world.fund_makers_default();
//!     world.start_makers(120);
//!     world.mine(1);
//!     maker_abort3_case2(&mut world, baseline);
//!     world.finish();
//! }
//! ```
//!
//! - `backend` is required. Every other key except `setup` is the
//!   `WorldBuilder` method of the same name: `key = value` calls
//!   `.key(value)`, a bare `key` calls `.key()`. Nothing is defaulted, except
//!   that `makers` is the length of a `maker_behaviors` list when omitted.
//! - `maker_behaviors` and `takers` see the `MakerBehavior` and
//!   `TakerBehavior` variants unqualified.
//! - `setup` lists `World` steps run in order after `build()`. `step(..) as x`
//!   binds the step's result to the body parameter named `x`.
//! - The body's first parameter receives the world; every later parameter
//!   must be bound by a setup step of the same name.
//! - The test is named after the body, which keeps its name when converted.
//! - Once the world is built, the test logs `Running Test: <name> - <first
//!   doc line>`, so the body needs no `warn!("Running Test: ...")` of its own.

use std::collections::HashSet;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use syn::{
    parse::Parser, punctuated::Punctuated, spanned::Spanned, Error, Expr, FnArg, Ident, ItemFn,
    Meta, Pat, Result, Token, Type, TypePath,
};

/// Turns a scenario body into a `#[test]` that builds its world, runs its
/// setup steps, calls the body and finishes the world. See the crate docs.
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

fn expand(args: TokenStream2, item: TokenStream2) -> Result<TokenStream2> {
    let metas = Punctuated::<Meta, Token![,]>::parse_terminated.parse2(args)?;
    let mut body: ItemFn = syn::parse2(item)?;
    // Mixed-site: test code cannot name, and so cannot shadow, the world.
    let world = Ident::new("world", Span::mixed_site());

    let mut seen = HashSet::new();
    let mut backend = None;
    let mut steps = Vec::new();
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
    let backend = backend.ok_or_else(|| {
        Error::new(
            Span::call_site(),
            "`backend = ...` is required, e.g. `backend = BitcoindBackend`",
        )
    })?;
    if let (false, Some(count)) = (makers_given, maker_count) {
        builder_calls.insert(0, quote!(.makers(#count)));
    }

    if let Some(test) = body.attrs.iter().find(|attr| attr.path().is_ident("test")) {
        return Err(Error::new(
            test.span(),
            "#[world_test] adds #[test] itself; remove this one",
        ));
    }
    if !body.sig.generics.params.is_empty() || body.sig.asyncness.is_some() {
        return Err(Error::new(
            body.sig.span(),
            "a #[world_test] body is a plain, non-generic fn",
        ));
    }

    // The first parameter takes the world; the rest come from setup bindings.
    let mut inputs = body.sig.inputs.iter();
    if inputs.next().is_none() {
        return Err(Error::new(
            body.sig.span(),
            "the body takes the world first, e.g. `world: &mut World`",
        ));
    }
    let bound: HashSet<String> = steps
        .iter()
        .filter_map(|step| step.binding.as_ref().map(Ident::to_string))
        .collect();
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
                format!("no setup step binds `{name}`; add `... as {name}` to `setup`"),
            ));
        }
        call_args.push(name);
    }

    let attrs = std::mem::take(&mut body.attrs);
    body.vis = syn::Visibility::Inherited;
    let name = body.sig.ident.clone();
    let running = running_line(&name, &attrs);
    let step_stmts = steps.iter().map(|step| {
        let call = &step.call;
        match &step.binding {
            Some(binding) => quote!(let #binding = #call;),
            None => quote!(#call;),
        }
    });

    Ok(quote! {
        #(#attrs)*
        #[test]
        fn #name() {
            #body
            let mut #world = crate::test_framework::World::builder::<#backend>()
                #(#builder_calls)*
                .build();
            // After build: the framework sets the logger up.
            ::log::warn!("{}", #running);
            #(#step_stmts)*
            #name(&mut #world, #(#call_args),*);
            #world.finish();
        }
    })
}

/// `Running Test: <name> - <first doc line>`, or just the name without docs.
fn running_line(name: &Ident, attrs: &[syn::Attribute]) -> String {
    let summary = attrs.iter().find_map(|attr| match &attr.meta {
        Meta::NameValue(nv) if nv.path.is_ident("doc") => match &nv.value {
            Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(doc),
                ..
            }) => Some(doc.value().trim().to_string()),
            _ => None,
        },
        _ => None,
    });
    match summary {
        Some(summary) if !summary.is_empty() => format!("Running Test: {name} - {summary}"),
        _ => format!("Running Test: {name}"),
    }
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
                "no setup step binds `baseline`",
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
}
