#!/bin/bash
# NIC Performance Tuning for High-Throughput Capture
# Optimiert alle i40e-Interfaces (>= 5 Gbps) automatisch:
#   1. Ring Buffer auf Maximum
#   2. Adaptive Coalescing aus (minimale Latenz)
#   3. IRQ Affinity: Jedes Interface bekommt eigene CPU-Gruppe
#   4. RPS: Softirq-Last auf mehrere CPUs verteilen

logger "NIC-Tuning: Starte Optimierung..."

CPU_COUNT=$(nproc)

# Alle i40e-Interfaces mit Link finden
IFACES=()
for iface in /sys/class/net/*/device/driver; do
    driver=$(basename $(readlink -f "$iface"))
    ifname=$(echo "$iface" | cut -d'/' -f5)
    [ "$driver" \!= "i40e" ] && continue
    # Nur Interfaces mit Link (carrier=1)
    carrier=$(cat /sys/class/net/$ifname/carrier 2>/dev/null)
    [ "$carrier" \!= "1" ] && continue
    IFACES+=("$ifname")
done

if [ ${#IFACES[@]} -eq 0 ]; then
    logger "NIC-Tuning: Keine aktiven i40e-Interfaces gefunden, ueberspringe."
    exit 0
fi

CPUS_PER_IFACE=$((CPU_COUNT / ${#IFACES[@]}))
[ $CPUS_PER_IFACE -lt 1 ] && CPUS_PER_IFACE=1

for idx in $(seq 0 $((${#IFACES[@]} - 1))); do
    iface=${IFACES[$idx]}
    cpu_start=$((idx * CPUS_PER_IFACE))
    cpu_end=$((cpu_start + CPUS_PER_IFACE - 1))
    [ $cpu_end -ge $CPU_COUNT ] && cpu_end=$((CPU_COUNT - 1))

    # 1. Ring Buffer auf Maximum
    max_rx=$(ethtool -g $iface 2>/dev/null | awk '/Pre-set/,/Current/' | grep 'RX:' | head -1 | awk '{print $2}')
    max_tx=$(ethtool -g $iface 2>/dev/null | awk '/Pre-set/,/Current/' | grep 'TX:' | head -1 | awk '{print $2}')
    [ -n "$max_rx" ] && ethtool -G $iface rx $max_rx 2>/dev/null
    [ -n "$max_tx" ] && ethtool -G $iface tx $max_tx 2>/dev/null

    # 2. Adaptive Coalescing deaktivieren
    ethtool -C $iface adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0 2>/dev/null

    # 3. IRQ Affinity
    i=0
    for irq in $(grep "i40e-${iface}-TxRx" /proc/interrupts | awk '{print $1}' | tr -d ':'); do
        cpu=$((cpu_start + i % CPUS_PER_IFACE))
        echo $cpu > /proc/irq/$irq/smp_affinity_list 2>/dev/null
        i=$((i + 1))
    done

    # 4. RPS fuer alle RX-Queues
    mask=0
    for c in $(seq $cpu_start $cpu_end); do
        mask=$((mask | (1 << c)))
    done
    hex_mask=$(printf '%x' $mask)
    for q in /sys/class/net/$iface/queues/rx-*/rps_cpus; do
        echo $hex_mask > $q 2>/dev/null
    done
    for q in /sys/class/net/$iface/queues/rx-*/rps_flow_cnt; do
        echo 32768 > $q 2>/dev/null
    done

    logger "NIC-Tuning: $iface -> CPU $cpu_start-$cpu_end (Ring=$max_rx, IRQs=$i)"
done

echo 65536 > /proc/sys/net/core/rps_sock_flow_entries 2>/dev/null
logger "NIC-Tuning: Optimierung abgeschlossen (${#IFACES[@]} Interfaces)."

# 5. Kernel netdev_budget erhöhen (verhindert port.rx_discards bei hohem pps)
sysctl -w net.core.netdev_budget=4096
sysctl -w net.core.netdev_budget_usecs=16000
logger "NIC-Tuning: netdev_budget=4096, budget_usecs=16000"

# 6. Backlog vergroessern (verhindert softnet drops bei single-queue non-IP traffic)
sysctl -w net.core.netdev_max_backlog=200000
logger "NIC-Tuning: netdev_max_backlog=200000"
