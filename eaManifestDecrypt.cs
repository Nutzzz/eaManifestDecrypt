using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml;
using SHA3.Net;
using static System.Environment;

namespace eaManifestDecrypt;

// EA (formerly Origin)
// [installed games + owned games; accurate titles only if login is provided]
public class eaManifestDecrypt
{
    public const string PROTOCOL = "origin2://"; //"eadm://" and "ealink://" added after move to EA branding, but "origin://" or "origin2://" still seem to be the correct ones
    public const string LAUNCH = PROTOCOL + "library/open";
    public const string START_GAME = PROTOCOL + "game/launch?offerIds=";
    public const string EA_REG = "EA Desktop";
    private const string EA_DB = @"EA Desktop\530c11479fe252fc5aabc24935b9776d4900eb3ba58fdc271e0d6229413ad40e\IS"; // ProgramData
    private const string EA_KEY_PREFIX = "allUsersGenericIdIS";

    private const string EA_LANGDEF = "en_US";
    private const string ORIGIN_CTRYDEF = "US";
    private const string ORIGIN_CONTENT = @"Origin\LocalContent"; // ProgramData
    private const string ORIGIN_PATH = "dipinstallpath=";

    private const string WMI_CLASS_MOBO = "Win32_BaseBoard";
    private const string WMI_CLASS_BIOS = "Win32_BIOS";
    private const string WMI_CLASS_VID = "Win32_VideoController";
    private const string WMI_CLASS_PROC = "Win32_Processor";
    private const string WMI_PROP_MFG = "Manufacturer";
    private const string WMI_PROP_SERIAL = "SerialNumber";
    private const string WMI_PROP_PNPID = "PNPDeviceID";
    private const string WMI_PROP_NAME = "Name";
    private const string WMI_PROP_PROCID = "ProcessorID";

    private static readonly string _hwfile = "ead_hwinfo.txt";
    private readonly static byte[] _ea_iv = { 0x84, 0xef, 0xc4, 0xb8, 0x36, 0x11, 0x9c, 0x20, 0x41, 0x93, 0x98, 0xc3, 0xf3, 0xf2, 0xbc, 0xef, };

    [SupportedOSPlatform("windows")]
    public static void Decrypt()
    {
        List<string[]> ownedGames = new();

        // Get games installed by EA Desktop client

        string dbFile = Path.Combine(GetFolderPath(SpecialFolder.CommonApplicationData), EA_DB);
        if (!File.Exists(dbFile))
        {
            Console.WriteLine("EA App installed game database not found.");
            return;
        }

        bool hwFail = false;
        string hwInfo = "";

        if (!GetHardwareInfo())
            hwFail = true;
        else
        {
            try
            {
                hwInfo = File.ReadAllText(_hwfile);
                if (string.IsNullOrEmpty(hwInfo))
                    hwFail = true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                hwFail = true;
            }
        }

        if (hwFail)
        {
            Console.WriteLine("Could not get hardware info for EA App installed game database decryption.");
            return;
        }

        if (!DecryptISFile(dbFile, hwInfo, out string strDocumentData) && !string.IsNullOrEmpty(strDocumentData))
        {
            Console.WriteLine("Could not decrypt database. You may need to open the EA App to update it.");
            return;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(@strDocumentData, new() { AllowTrailingCommas = true });
            if (document.RootElement.TryGetProperty("installInfos", out JsonElement gameArray))
            {
                foreach (JsonElement game in gameArray.EnumerateArray())
                {
                    bool dlc = false;
                    string slug = "";
                    string regKey = "";
                    string instPath = "";
                    string exeFile = "";
                    string titleTmp = "";

                    bool bInstalled = false;
                    string strID = "";
                    string strTitle = "";
                    string strLaunch = "";
                    string strUninstall = "";
                    DateTime lastRun = DateTime.MinValue;

                    instPath = GetStringProperty(game, "baseInstallPath") ?? "";
                    if (!string.IsNullOrEmpty(instPath))
                        bInstalled = true;
                    slug = GetStringProperty(game, "baseSlug") ?? "";
                    // this only catches some DLC
                    /*
                    dlc = string.IsNullOrEmpty(GetStringProperty(game, "dlcSubPath")) ? false : true;
                    if (dlc)
                        continue;
                    */
                    strID = GetStringProperty(game, "softwareId") ?? "";

                    foreach (string[] ownedGame in ownedGames)
                    {
                        if (ownedGame.Length > 1 && ownedGame[0].Equals(strID))
                        {
                            strID = ownedGame[0];
                            strTitle = ownedGame[1];
                            // lastRun doesn't work
                            if (!(ownedGame.Length > 3 && DateTime.TryParse(ownedGame[3], out lastRun)))
                                lastRun = DateTime.MinValue;
                        }
                    }
                    if (string.IsNullOrEmpty(strTitle))
                    {
                        TextInfo ti = new CultureInfo("en-US", false).TextInfo;
                        strTitle = ti.ToTitleCase(slug.Replace("-", " "));
                    }

                    if (bInstalled)
                    {
                        string exeCheck = GetStringProperty(game, "executableCheck") ?? "";
                        if (exeCheck.StartsWith('['))
                        {
                            int i = exeCheck.IndexOf(']');
                            if (i > 1)
                                regKey = exeCheck.Substring(1, i);
                            exeFile = exeCheck[(i + 1)..];
                            strLaunch = Path.Combine(instPath, exeFile);

                            string instFile = Path.Combine(instPath, @"__Installer\installerdata.xml");
                            if (File.Exists(instFile))
                            {
                                XmlDocument doc = new();
                                doc.Load(instFile);
                                var gameTitles = doc.SelectNodes("//DiPManifest/gameTitles/gameTitle");
                                if (gameTitles is not null)
                                {
                                    foreach (XmlNode gameTitle in gameTitles)
                                    {
                                        if (gameTitle?.Attributes?["locale"]?.Value == EA_LANGDEF)
                                        {
                                            titleTmp = gameTitle.InnerText;
                                            if (!string.IsNullOrEmpty(titleTmp))
                                                strTitle = titleTmp;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        game.TryGetProperty("localUninstallProperties", out JsonElement uninst);
                        strUninstall = "\"" + GetStringProperty(uninst, "uninstallCommand") ?? "" + "\"";
                        string uninstParam = GetStringProperty(uninst, "uninstallParameters") ?? "";
                        if (!string.IsNullOrEmpty(uninstParam))
                            strUninstall += " " + uninstParam;
                    }

                    Console.WriteLine("* {0}\n  Software Id: {1}", strTitle, strID);
                    if (bInstalled)
                        Console.WriteLine("  Executable: {0}\n  Uninstall: {1}", strLaunch, strUninstall);
                }
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(string.Format("Malformed EA manifest file.\n{0}", e.Message));
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? GetWMIValue(string property, string path)
    {
        ManagementObjectSearcher mos = new(new SelectQuery(string.Format("SELECT {0} FROM {1}", property, path)));
        foreach (ManagementObject result in mos.Get().Cast<ManagementObject>())
        {
            return result.GetPropertyValue(property).ToString();
        }
        return null;
    }

    [SupportedOSPlatform("windows")]
    internal static bool GetHardwareInfo()
    {
        StringBuilder sb = new();

        try
        {
            sb.Append(GetWMIValue(WMI_PROP_MFG, WMI_CLASS_MOBO));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_SERIAL, WMI_CLASS_MOBO));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_MFG, WMI_CLASS_BIOS));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_SERIAL, WMI_CLASS_BIOS));
            sb.Append(';');
            sb.Append(GetVolumeInformationW(@"C:\", null!, 0, out uint drvsn, out _, out _, null!, 0) ?
                drvsn.ToString("X", CultureInfo.InvariantCulture) :
                "");
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_PNPID, WMI_CLASS_VID));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_MFG, WMI_CLASS_PROC));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_PROCID, WMI_CLASS_PROC));
            sb.Append(';');
            sb.Append(GetWMIValue(WMI_PROP_NAME, WMI_CLASS_PROC));
            sb.Append(';');

            string hwInfo = sb.ToString();
            Console.WriteLine("EA hardware info:\n{0}\n", hwInfo);
            if (!File.Exists(_hwfile))
                File.WriteAllText(_hwfile, hwInfo);
            return true;
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
        return false;
    }

    /// <summary>
    /// Retrieve string value from the JSON element
    /// </summary>
    /// <param name="strPropertyName">Name of the property</param>
    /// <param name="jElement">Source JSON element</param>
    /// <returns>Value of the property as a string or empty string if not found</returns>
    public static string? GetStringProperty(JsonElement jElement, string strPropertyName)
    {
        try
        {
            if (jElement.TryGetProperty(strPropertyName, out JsonElement jValue))
            {
                if (jValue.ValueKind.Equals(JsonValueKind.String))
                    return jValue.GetString();
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.Message);
        }
        return null;
    }

    private static byte[] CalculateKey(string hwInfo)
    {
        int byteCount = 0;

        // Calculate SHA1 Hash of hardware string
        ReadOnlySpan<char> hwInfoSpan = hwInfo.AsSpan();
        byteCount = Encoding.ASCII.GetByteCount(hwInfoSpan);
        Span<byte> hwHashSpan = byteCount < 1024 ? stackalloc byte[byteCount] : new byte[byteCount];
        Encoding.ASCII.GetBytes(hwInfoSpan, hwHashSpan);
        Span<byte> hwBuff = stackalloc byte[20];
        SHA1.HashData(hwHashSpan, hwBuff);

        string hash = EA_KEY_PREFIX + Convert.ToHexString(hwBuff).ToLower(CultureInfo.InvariantCulture);

        // Calculate SHA3 256 Hash of full string
        byteCount = Encoding.ASCII.GetByteCount(hash);
        byte[] keyBuff = new byte[byteCount];
        Encoding.ASCII.GetBytes(hash.AsSpan(), keyBuff.AsSpan());

        using Sha3 sha3 = Sha3.Sha3256();
        return sha3.ComputeHash(keyBuff);
    }

    private static bool DecryptISFile(string dbFile, string hwInfo, out string decryptedText)
    {
        try
        {
            byte[] key = CalculateKey(hwInfo);
            byte[] encryptedText = File.ReadAllBytes(dbFile);

            // skips the first 64 bytes, because they contain a hash we don't need
            using MemoryStream ms = new(encryptedText, 64, encryptedText.Length - 64, writable: false);
            using Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Key = key;
            aes.IV = _ea_iv;

            ICryptoTransform dec = aes.CreateDecryptor(aes.Key, aes.IV);
            using CryptoStream cs = new(ms, dec, CryptoStreamMode.Read);
            using StreamReader sr = new(cs);
            decryptedText = sr.ReadToEnd();
            return true;
        }
        catch (Exception e)
        {
            Console.WriteLine(string.Format("Malformed EA manifest file.\n{0}", e.Message));
        }
        decryptedText = "";
        return false;
    }

#nullable enable
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool GetVolumeInformationW(
        string lpRootPathName,
        StringBuilder? lpVolumeNameBuffer,
        int nVolumeNameSize,
        out uint lpVolumeSerialNumber,
        out uint lpMaximumComponentLength,
        out uint lpFileSystemFlags,
        StringBuilder? lpFileSystemNameBuffer,
        int nFileSystemNameSize);
}
#nullable restore
