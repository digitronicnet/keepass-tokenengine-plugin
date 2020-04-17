using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using TokenEngineKeyProvider.Common;

namespace TokenEngineKeyProvider
{
    class SymmetricKeyData : Disposable
    {
        public const ushort CurrentVersion = 1;
        public const int KeyLength = 32;

        public static SymmetricKeyData Generate()
        {
            var rnd = new Random();
            var key = new byte[KeyLength];

            try
            {
                rnd.NextBytes(key);
                return new SymmetricKeyData(CurrentVersion, 0, key);
            }
            finally
            {
                Array.Clear(key, 0, key.Length);
            }
        }

        public static SymmetricKeyData Load(byte[] data)
        {
            using(var ms = new MemoryStream(data, writable: false))
            using (var br = new BinaryReader(ms))
            {
                var version = br.ReadUInt16();
                var flags = br.ReadUInt16();

                switch(version)
                {
                    case 1:
                        var keyLength = 32;
                        var key = br.ReadBytes(keyLength);
                        if (key.Length != keyLength)
                            throw new InvalidDataException($"The stored key has an invalid size. Key length is '{key.Length}', but expected was '{keyLength}'.");
                        return new SymmetricKeyData(version, flags, key, data);
                    default:
                        throw new NotSupportedException($"A data format with version '{version}' is not supported.");
                }
            }
        }

        public ushort Version { get; private set; }

        public ushort Flags { get; private set; }

        public byte[] Key { get; private set; }

        public byte[] RawData { get; private set; }

        private SymmetricKeyData(ushort version, ushort flags, byte[] key, byte[] rawData = null)
        {
            Version = version;
            Flags = flags;

            Key = new byte[key.Length];
            Array.Copy(key, Key, key.Length);

            if (rawData == null)
            {
                using (var ms = new MemoryStream())
                using (var bw = new BinaryWriter(ms))
                {
                    bw.Write(version);
                    bw.Write(flags);
                    bw.Write(key);

                    RawData = ms.ToArray();
                }
            }
            else
            {
                RawData = new byte[rawData.Length];
                Array.Copy(rawData, RawData, rawData.Length);
            }
        }

        protected override void DisposeManaged()
        {
            Array.Clear(Key, 0, Key.Length);
            Array.Clear(RawData, 0, RawData.Length);

            base.DisposeManaged();
        }
    }
}
