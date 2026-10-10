/* OpenSwap uses ZeroMQ over TCP only. Avoid libzmq 4.3.4's crashing Windows IPC path. */
#undef ZMQ_HAVE_IPC
