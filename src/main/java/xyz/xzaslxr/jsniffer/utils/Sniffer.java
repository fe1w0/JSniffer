package xyz.xzaslxr.jsniffer.utils;

import javafx.collections.ObservableList;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.File;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

public class Sniffer {
    private PcapNetworkInterface localInterface;

    private static Short PCAP_COUNTER = 0;

    public Sniffer(PcapNetworkInterface netInterface) {
        this.localInterface = netInterface;
    }


    public static CopyOnWriteArrayList<PacketModel> getFilterPacketList(PcapHandle pcapHandle, String bpf, CopyOnWriteArrayList<PacketModel> gotPackets) throws Exception {
        // try {
        CopyOnWriteArrayList<PacketModel> packetList = new CopyOnWriteArrayList<PacketModel>();
        for (PacketModel packetModel : gotPackets) {
            if (judgeFilter(pcapHandle, bpf, packetModel.getItemPacket())) {
                packetList.add(packetModel);
                // System.out.println(packetModel.getItemPacket());
            }
        }
        return packetList;
        // } catch (Exception e) {
        //     System.out.println(bpf);
        //     e.printStackTrace();
        //     return new CopyOnWriteArrayList<PacketModel>();
        // }
    }

    public static boolean judgeFilter(PcapHandle pcapHandle, String bpf, Packet packet) throws Exception {
        // https://github.com/kaitoy/pcap4j/blob/0b4fad83439808c32f61054b2693641991572f6f/pcap4j-core/src/main/java/org/pcap4j/core/BpfProgram.java
        // https://github.com/kaitoy/pcap4j/blob/0b4fad83439808c32f61054b2693641991572f6f/pcap4j-core/src/test/java/org/pcap4j/core/BpfProgramTest.java
        if (bpf == "") {
            return true;
        } else {
            BpfProgram bpfProgram = pcapHandle.compileFilter(bpf, BpfProgram.BpfCompileMode.OPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN);
            return bpfProgram.applyFilter(packet);
        }
    }

    public static PcapHandle getPcapHandler(PcapNetworkInterface networkInterface) throws Exception {
        PcapHandle handle = networkInterface.openLive(65536, // snaplen ???????????????????????????????????????
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, // mode ??????????????? promiscuous ??????
                10); // timeout ?????????????????????
        return handle;
    }

    static public void runSniffer(PcapHandle handle, List<PacketModel> gotPackets, ObservableList<PacketModel> packetsTable) throws Exception{
        // ?????? ?????????
        // Debug filter
        // String filter = "dst port 443";
        // handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        PacketListener packetListener = packet -> {
            if (packet != null) {
                try {
                    PacketModel packetModel = new PacketModel(handle.getTimestamp(), PCAP_COUNTER++, packet);
                    packetsTable.add(packetModel);
                    gotPackets.add(packetModel);
                } catch (Exception e) {
                    System.out.println("[!] Error PacketModel");
                    e.printStackTrace();
                }
            }
        };

        // ????????????
        try {
            // -1 ??????????????????
            int maxPacketSize = -1;
            handle.loop(maxPacketSize, packetListener);
        } catch (InterruptedException i) {
            System.out.println("[+] End loop");
        } catch (Exception e) {
            System.out.println("[!] Error: runSniffer");
            e.printStackTrace();
        }
    }

    public static void savePackets(PcapHandle handle, File pcapFile, CopyOnWriteArrayList<PacketModel> packetModels) throws Exception {
        PcapDumper dumper = handle.dumpOpen(pcapFile.getAbsolutePath()); // ?????? Dump .pcap ??????
        for (PacketModel packetModel : packetModels) {
            dumper.dump(packetModel.getItemPacket());
        }
        dumper.close();
        // handle.close();
    }

    public static void openPacketFile(PcapHandle openFilePcapHandle, List<PacketModel> gotPackets, ObservableList<PacketModel> packetsTable) throws Exception {
        Packet packet = null;
        PacketListener packetListener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                if (packet != null) {
                    try {
                        PacketModel packetModel = new PacketModel(openFilePcapHandle.getTimestamp(), PCAP_COUNTER++, packet);
                        packetsTable.add(packetModel);
                        gotPackets.add(packetModel);
                    } catch (Exception e) {
                        System.out.println("[!] Error PacketModel");
                        e.printStackTrace();
                    }
                }
            }
        };

        try {
            // -1 ??????????????????
            int maxPacketSize = -1;
            openFilePcapHandle.loop(maxPacketSize, packetListener);
        } catch (InterruptedException i) {
            openFilePcapHandle.breakLoop();
            // openFilePcapHandle.close();
            System.out.println("[+] End loop");
        } catch (Exception e) {
            openFilePcapHandle.breakLoop();
            // openFilePcapHandle.close();
            System.out.println("[!] Error: runSniffer");
            e.printStackTrace();
        }

    }

    public static void zeroCounter() throws Exception {
        PCAP_COUNTER = 0;
    }

}
