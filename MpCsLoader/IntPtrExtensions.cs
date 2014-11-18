using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace Shared
{
    public static class IntPtrExtensions
    {
        public static IntPtr Increment(IntPtr ptr, int cbSize)
        {
#if AMD64
            return new IntPtr(ptr.ToInt64() + cbSize);
#else
            return new IntPtr(ptr.ToInt32() + cbSize);
#endif
        }

        public static IntPtr Increment(IntPtr ptr)
        {
            return Increment(ptr, Marshal.SizeOf(typeof(IntPtr)));
        }

        public static IntPtr ElementAt(IntPtr ptr, int index)
        {
            var offset = IntPtr.Size * index;
            var offsetPtr = Increment(ptr, offset);
            return offsetPtr;
        }
    }
}
