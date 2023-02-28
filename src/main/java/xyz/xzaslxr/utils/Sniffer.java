package xyz.xzaslxr.utils;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;

import java.util.List;



public class Sniffer {
    private PcapNetworkInterface localInterface;

    private static Short PCAP_COUNTER = 0;

    public Sniffer(PcapNetworkInterface netInterface) {
        this.localInterface = netInterface;
    }

    public static PcapHandle getPcapHandler(PcapNetworkInterface networkInterface) throws Exception {
        PcapHandle handle = networkInterface.openLive(65536, // snaplen 参数为捕获数据包的最大长度
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, // mode 参数为设置 promiscuous 模式
                10); // timeout 参数为超时时间
        return handle;
    }

    static public void runSniffer(PcapHandle handle, List<PacketModel> gotPackets) throws Exception{
        // 设置 监听器
        PacketListener packetListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (packet != null) {
                    gotPackets.add(new PacketModel(handle.getTimestamp(), PCAP_COUNTER++, packet));
                }
                // // Debug
                // System.out.println("Packets Length: " + gotPackets.size());
                // System.out.println(packet);
            }
        };

        // 试试获取
        try {
            // -1 表示无限循环
            int maxPacketSize = -1;
            handle.loop(maxPacketSize, packetListener);
        } catch (InterruptedException i) {
            System.out.println("[+] End loop");
        } catch (Exception e) {
            System.out.println("[!] Error: runSniffer");
            e.printStackTrace();
        }
    }

    public static void zeroCounter() throws Exception {
        PCAP_COUNTER = 0;
    }



}
