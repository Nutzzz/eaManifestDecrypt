namespace eaManifestDecrypt;
class Program
{
    static void Main()
    {
        if (OperatingSystem.IsWindows())
            eaManifestDecrypt.Decrypt();
    }
}
