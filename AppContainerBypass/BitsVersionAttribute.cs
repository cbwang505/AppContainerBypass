#region License

//
// Copyright ?2009-2011 Ian Davis <ian@innovatian.com>
// 
// Dual-licensed under the Apache License, Version 2.0, and the Microsoft Public License (Ms-PL).
// See the file LICENSE.txt for details.
//

#endregion

#region Using Directives

using System;

#endregion

namespace AppContainerBypass
{
    public class BitsVersionAttribute : Attribute
    {
        public BitsVersionAttribute( BitsVersion version )
        {
            Version = version;
        }

        public BitsVersion Version { get; private set; }
    }

    public enum BitsVersion
    {
        Bits_10,
        Bits_15,
        Bits_20,
        Bits_25,
        Bits_30
    }
}