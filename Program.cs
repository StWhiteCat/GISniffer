using System;
using System.IO;
using System.Threading;
using PacketDotNet;
using SharpPcap;
using System.Text.Json;
using Google.Protobuf;

namespace GISniffer
{
    public class Program
    {
        private static readonly DateTime UtcOffset = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToUniversalTime();
        private static readonly String UnixTime = ((Int64)(DateTime.Now - UtcOffset).TotalSeconds).ToString();
        private static int packetCount = 0;
        private static string name;
        private static string keypath;
        private static int keytype=0;     
        enum EDirection
        {
            In,
            Out
        }
        private static byte[] xorData(byte[] arr, byte[] key)
        {
            byte[] result = new byte[arr.Length];    
            for (int i = 0; i < arr.Length; i++)
            {
                result[i] = (byte)(arr[i] ^ key[i % key.Length]);
            }  
            return result;
        }

        private static byte[] Slice(byte[] arr, int indexFrom, int indexTo)
        {
            if (indexFrom > indexTo)
            {
                Console.WriteLine("indexFrom is {0},indexTo is {1}", indexFrom,indexTo);
                throw new ArgumentOutOfRangeException("indexFrom is bigger than indexTo!");
            }
            int length = indexTo - indexFrom;
            byte[] result = new byte[length];
            Array.Copy(arr, indexFrom, result, 0, length);
            return result;
        }

        private static ushort Read16BitsBE(byte[] arr, int indexFrom)
        {  
            ushort s = 0;
            byte b1 = arr[indexFrom];
            byte b2 = arr[indexFrom+1];
            s = (ushort)(s ^ b1);
            s = (ushort)(s << 8);
            s = (ushort)(s ^ b2);
            return s;
        }
        private static string getProtoNameByPacketID(ushort id)
        {
            
            string text = File.ReadAllText("./packetids.json");
            using JsonDocument doc = JsonDocument.Parse(text);
            JsonElement root = doc.RootElement;
            var iter = root.EnumerateObject();
            while (iter.MoveNext())
            {
                var proto = iter.Current;
                if (proto.Name == id.ToString())
                {
                    name= proto.Value.ToString();
                    break;
                }
            }
            Console.WriteLine("This is inthe getProtoNameByPacketID function name is{0}",name);
            return name; 
        }

        private static void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                var rawPacket = Packet.ParsePacket(LinkLayers.Ethernet, e.Packet.Data).Extract<EthernetPacket>();
                var ipPacket = Packet.ParsePacket(LinkLayers.Ethernet, e.Packet.Data).Extract<IPv4Packet>();
                var udpPacket = ipPacket.Extract<UdpPacket>();
                EDirection direction = udpPacket.DestinationPort == 22101 ? EDirection.Out : EDirection.In;
                Console.WriteLine($"New {direction} packet with {udpPacket.PayloadData.Length} bytes");
                File.WriteAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Dumps", $"{packetCount.ToString("D5")}_{direction}.bin"), udpPacket.PayloadData);
                packetCount++;
            }
            catch (Exception ex) { Console.WriteLine(ex.ToString()); }
        }

        private static void Sniffer()
        {
            Console.WriteLine($"GISniffer{SharpPcap.Version.VersionString}");
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices available");
                return;
            }
            Console.WriteLine();
            Console.WriteLine("choose devices:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();
            var i = 0;
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }
            Console.WriteLine();
            Console.Write("choose a device: ");
            i = Int32.Parse(Console.ReadLine() ?? throw new InvalidOperationException());
            var device = devices[i];
            var readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            device.Filter = "udp portrange 22100-22102";
            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Dumps")))
                    Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Dumps"));
            }
            catch (Exception e) { Console.WriteLine(e.ToString()); }
            device.OnPacketArrival += Device_OnPacketArrival;
            device.StartCapture();
            Console.WriteLine();
            Console.WriteLine($"-- Listening on {device.Name}, hit 'c' to stop...");
            while (true)
            {
                var keyInfo = Console.ReadKey();
                if (keyInfo.Key == ConsoleKey.C)
                {
                    Thread.Sleep(500);
                    break;
                }
            }
            Console.WriteLine("-- Capture stopped");
            Console.WriteLine(device.Statistics.ToString());
            device.Close();
        }
        private static void Parsing()
        {
            Console.WriteLine("starting parsing bin files..."); 
            string file_path = "./Dumps/";
            var files = Directory.GetFiles(file_path, "*.bin");
            try
            {
                if (!Directory.Exists(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Parsed")))
                    Directory.CreateDirectory(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Parsed"));
            }
            catch (Exception e) { Console.WriteLine(e.ToString()); }
            foreach (var file in files)
            {    
                byte[] data = File.ReadAllBytes(file);   
                if (data.Length <= 28)//ur mom
                {
                    Console.WriteLine("raw packet {0} bytes less than 29!",file);
                }
                else
                {
                    byte[] dataWithoutKCP = Slice(data, 28, data.Length);
                    if (keytype.Equals(0))
                    {
                        keypath = "";
                    }
                    else
                    {
                        keypath = "";
                    }
                    byte[] key = File.ReadAllBytes(keypath);
                    byte[] xorP= xorData(dataWithoutKCP, key);
                    if (xorP.Length > 5 && Read16BitsBE(xorP, 0) == 0x4567 && Read16BitsBE(xorP, xorP.Length - 2) == 0x89AB)
                    {
                        Console.WriteLine("0x4567 packet: {0}", file);
                        ushort packetID = Read16BitsBE(xorP, 2);
                        string myProtoName = getProtoNameByPacketID(packetID);
                        byte[] removeMagic = Slice(Slice(xorP, 10, xorP.Length - 2), xorP[5], Slice(xorP, 10, xorP.Length - 2).Length);
                        byte[] parsedPacket = Slice(removeMagic, xorP[6], removeMagic.Length);
                        if (myProtoName == "")
                        {
                            Console.WriteLine("proto name of ID {0} not found!", packetID);
                        }
                        else if (packetID == 118)
                        {
                            try
                            {
                                if (myProtoName != "GetPlayerTokenRsp")
                                {
                                    Console.WriteLine("has been changed by mhy agent!");
                                }
                                else
                                {
                                    //ulong seed = ;
                                    //byte[] key2 = MT19937(seed);
                                    keytype = 1;
                                    try
                                    {
                                        File.WriteAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Parsed", $"{myProtoName}.bin"), parsedPacket);
                                    }
                                    catch (Exception ex)
                                    {
                                        Console.WriteLine(ex.Message);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                            }
                        }
                        else
                        {
                            Console.WriteLine("entered saving other packets!!!!!!!!!!");
                            try
                            {
                                File.WriteAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Parsed",$"{myProtoName}.bin"), parsedPacket);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                            }
                        }
                    }
                    else
                    {
                        Console.WriteLine("+++++++++++++{0} is NOT mhy packet+++++++++++++++++", file);
                    }
                }      
            }
        }
        static void Main(string[] args)
        {
            Console.WriteLine("GISniffer by Gold\n" +
                "Choose operation:\n" +
                "1.Sniffer Packet Without Parsing\n" +
                "2.Sniffer Packet and Parsing\n" +
                "3.Only Parsing\n");
            var choice = 0;
            choice = Int32.Parse(Console.ReadLine() ?? throw new InvalidOperationException());
            switch (choice)
            {
                case 1:
                    Sniffer();
                    break;
                case 2:
                    Sniffer();
                    Parsing();
                    break;
                case 3:
                    Parsing();
                    break;
                default:break;
            }
            Console.ReadLine();
        }  
    } 
}
