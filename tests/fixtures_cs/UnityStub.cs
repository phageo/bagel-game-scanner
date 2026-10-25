// Stand-ins for the Unity types the test libraries name (only their names and shapes
// matter: the scanner reads the test libraries, nothing is ever run).
using System;
using System.Collections;

namespace UnityEngine
{
    public class Object { }
    public class MonoBehaviour : Object
    {
        public object StartCoroutine(IEnumerator routine) { return null; }
    }
    public static class Debug
    {
        public static void Log(object message) { }
    }
    public class TextAsset : Object
    {
        public byte[] bytes { get { return null; } }
    }
    public static class Resources
    {
        public static T Load<T>(string path) where T : Object { return null; }
    }
    public class WWW
    {
        public WWW(string url) { }
        public byte[] bytes { get { return null; } }
        public string text { get { return null; } }
    }
}

namespace UnityEngine.Networking
{
    public class DownloadHandler
    {
        public byte[] data { get { return null; } }
        public string text { get { return null; } }
    }
    public class UnityWebRequest : IDisposable
    {
        public static UnityWebRequest Get(string uri) { return null; }
        public object SendWebRequest() { return null; }
        public DownloadHandler downloadHandler { get { return null; } }
        public bool isDone { get { return false; } }
        public void Dispose() { }
    }
}
