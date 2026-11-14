//! The one `forward_kernel!`: every platform's `Kernel` is also implemented by a borrow, a `Box` and
//! an `Arc` of a kernel, so a caller may hand a process any of them.
//!
//! Each platform lists its trait's methods in the call, as `fn name(&self, arg: Type, ..) -> Ret;`,
//! beside the trait that declares them. A trait with no methods writes `forward_kernel!();`.

macro_rules! forward_kernel {
    (
        @pointer [$pointer:ty] [$($bound:tt)+]
        $(fn $name:ident(&self $(, $arg:ident: $ty:ty)*) -> $ret:ty;)*
    ) => {
        impl<T: $($bound)+ + ?Sized> Kernel for $pointer {
            $(
                fn $name(&self $(, $arg: $ty)*) -> $ret {
                    (**self).$name($($arg),*)
                }
            )*
        }
    };
    ($($methods:tt)*) => {
        forward_kernel!(@pointer [&T] [Kernel] $($methods)*);
        forward_kernel!(@pointer [Box<T>] [Kernel] $($methods)*);
        // An `Arc<T>` is `Sync` only for a `T` that is `Send` too.
        forward_kernel!(@pointer [std::sync::Arc<T>] [Kernel + Send] $($methods)*);
    };
}
