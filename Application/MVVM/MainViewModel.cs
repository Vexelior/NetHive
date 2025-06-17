using LiveChartsCore.SkiaSharpView.Painting;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore;
using SkiaSharp;
using System.Collections.ObjectModel;
using System.Net.NetworkInformation;
using System.Timers;
using Timer = System.Timers.Timer;
using PacketDotNet;
using SharpPcap;
using System.Net;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.ComponentModel;
using System.Linq;
using System.Collections.Generic;

namespace Application.MVVM;

public class MainViewModel : INotifyPropertyChanged
{
    public ISeries[] NetworkSeries { get; set; }
    public Axis[] XAxes { get; set; }
    public Axis[] YAxes { get; set; }

    private readonly LineSeries<double> _uploadSeries;
    private readonly LineSeries<double> _downloadSeries;
    private readonly Timer _timer;
    private ICaptureDevice _snifferDevice;

    public Queue<double> UploadValues { get; } = new();
    public Queue<double> DownloadValues { get; } = new();

    public ObservableCollection<string> SniffedPackets { get; } = new();

    private readonly ConcurrentDictionary<IPAddress, string> _dnsCache = new();

    private string _dnsFilterText = string.Empty;
    public string DnsFilterText
    {
        get => _dnsFilterText;
        set
        {
            if (_dnsFilterText != value)
            {
                _dnsFilterText = value;
                OnPropertyChanged(nameof(DnsFilterText));
                OnPropertyChanged(nameof(FilteredSniffedPackets));
            }
        }
    }

    public IEnumerable<string> FilteredSniffedPackets =>
        string.IsNullOrWhiteSpace(DnsFilterText)
            ? SniffedPackets
            : SniffedPackets.Where(p => p.Contains(DnsFilterText, StringComparison.OrdinalIgnoreCase));

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged(string propertyName) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    public MainViewModel()
    {
        _uploadSeries = new LineSeries<double>
        {
            Values = new ObservableCollection<double>(),
            Name = "Upload KB/s",
            Stroke = new SolidColorPaint(SKColors.Red, 2),
            GeometrySize = 0
        };

        _downloadSeries = new LineSeries<double>
        {
            Values = new ObservableCollection<double>(),
            Name = "Download KB/s",
            Stroke = new SolidColorPaint(SKColors.Blue, 2),
            GeometrySize = 0
        };

        var whitePaint = new SolidColorPaint(SKColors.White);

        NetworkSeries = [_uploadSeries, _downloadSeries];
        XAxes = [new Axis { Name = "Time", LabelsPaint = whitePaint, NamePaint = whitePaint }];
        YAxes = [new Axis { Name = "Speed (KB/s)", LabelsPaint = whitePaint, NamePaint = whitePaint }];

        _timer = new Timer(1000);
        _timer.Elapsed += OnTimerElapsed;
        _timer.Start();

        Task.Run(StartPacketSniffing);
    }

    private long _lastUpload = 0;
    private long _lastDownload = 0;

    private void OnTimerElapsed(object sender, ElapsedEventArgs e)
    {
        var nic = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up &&
                                 (n.Name.Contains("Wi-Fi") || n.Name.Contains("Ethernet")));

        if (nic == null)
        {
            return;
        }

        var stats = nic.GetIPv4Statistics();
        long currentUpload = stats.BytesSent;
        long currentDownload = stats.BytesReceived;

        double uploadSpeed = _lastUpload > 0 ? Math.Round((currentUpload - _lastUpload) / 1024.0, 2) : 0;
        double downloadSpeed = _lastDownload > 0 ? Math.Round((currentDownload - _lastDownload) / 1024.0, 2) : 0;

        _lastUpload = currentUpload;
        _lastDownload = currentDownload;

        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            if (_uploadSeries.Values is ObservableCollection<double> u)
            {
                u.Add(uploadSpeed);
                if (u.Count > 30) u.RemoveAt(0);
            }
            if (_downloadSeries.Values is ObservableCollection<double> d)
            {
                d.Add(downloadSpeed);
                if (d.Count > 30) d.RemoveAt(0);
            }
        });
    }

    private void StartPacketSniffing()
    {
        var devices = CaptureDeviceList.Instance;
        if (devices.Count < 1)
        {
            Console.WriteLine("No devices found.");
            return;
        }

        _snifferDevice = devices.FirstOrDefault(x => x.Description.Equals("Realtek PCIe GbE Family Controller", StringComparison.CurrentCultureIgnoreCase)) ?? throw new InvalidOperationException("No suitable sniffing device found.");

        _snifferDevice.OnPacketArrival += OnPacketArrival;
        _snifferDevice.Open(DeviceModes.Promiscuous, 1000);
        _snifferDevice.StartCapture();
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        try
        {
            var packet = Packet.ParsePacket(e.GetPacket().LinkLayerType, e.GetPacket().Data);
            var ip = packet.Extract<IPPacket>();
            var tcp = packet.Extract<TcpPacket>();
            var udp = packet.Extract<UdpPacket>();

            string info = $"[{DateTime.Now:HH:mm:ss}] ";
            if (ip != null)
            {
                var srcIp = ip.SourceAddress;
                var dstIp = ip.DestinationAddress;

                string srcHost = GetHostOrIp(srcIp);
                string dstHost = GetHostOrIp(dstIp);

                info += $"IP {srcHost} -> {dstHost}";
                if (tcp != null)
                    info += $" TCP {tcp.SourcePort} -> {tcp.DestinationPort}";
                else if (udp != null)
                    info += $" UDP {udp.SourcePort} -> {udp.DestinationPort}";

                _ = ResolveAndUpdateHost(srcIp);
                _ = ResolveAndUpdateHost(dstIp);
            }
            else
            {
                info += "Non-IP packet";
            }

            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                SniffedPackets.Add(info);
                if (SniffedPackets.Count > 100) SniffedPackets.RemoveAt(0);
                OnPropertyChanged(nameof(FilteredSniffedPackets));
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine("Packet parse error: " + ex.Message);
        }
    }

    private string GetHostOrIp(IPAddress ip)
    {
        if (ip == null) return "";
        if (_dnsCache.TryGetValue(ip, out var host) && !string.IsNullOrWhiteSpace(host) && host != ip.ToString())
            return $"{host} ({ip})";
        return ip.ToString();
    }

    private async Task ResolveAndUpdateHost(IPAddress ip)
    {
        if (ip == null || _dnsCache.ContainsKey(ip)) return;
        try
        {
            var entry = await Dns.GetHostEntryAsync(ip);
            if (!string.IsNullOrEmpty(entry.HostName))
            {
                _dnsCache[ip] = entry.HostName;
            }
            else
            {
                _dnsCache[ip] = ip.ToString();
            }
        }
        catch
        {
            _dnsCache[ip] = ip.ToString();
        }
    }
}
