from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO, emit
from scapy.all import sniff, IP, TCP, UDP, ICMP
from threading import Thread, Event
import time
from collections import defaultdict

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')


# Storage for statistics
traffic_stats = {
    'total_packets': 0,
    'protocols': defaultdict(int),
    'ips': defaultdict(int),
    'recent_packets': []
}

# Threading control
sniffer_thread = None
stats_thread = None
stop_event = Event()

def packet_callback(packet):
    """Process each captured packet (called by Scapy)"""
    global traffic_stats
    
    if IP in packet:
        traffic_stats['total_packets'] += 1
        
        packet_info = {
            'timestamp': time.strftime('%H:%M:%S'),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'size': len(packet)
        }
        
        if TCP in packet:
            packet_info['protocol_name'] = 'TCP'
            packet_info['src_port'] = packet[TCP].sport
            packet_info['dst_port'] = packet[TCP].dport
            traffic_stats['protocols']['TCP'] += 1
        elif UDP in packet:
            packet_info['protocol_name'] = 'UDP'
            packet_info['src_port'] = packet[UDP].sport
            packet_info['dst_port'] = packet[UDP].dport
            traffic_stats['protocols']['UDP'] += 1
        elif ICMP in packet:
            packet_info['protocol_name'] = 'ICMP'
            packet_info['src_port'] = '-'
            packet_info['dst_port'] = '-'
            traffic_stats['protocols']['ICMP'] += 1
        else:
            packet_info['protocol_name'] = 'Other'
            packet_info['src_port'] = '-'
            packet_info['dst_port'] = '-'
            traffic_stats['protocols']['Other'] += 1
        
        traffic_stats['ips'][packet[IP].src] += 1
        
        # Add to recent packets and trim
        traffic_stats['recent_packets'].insert(0, packet_info)
        if len(traffic_stats['recent_packets']) > 50:
            traffic_stats['recent_packets'].pop()
        
        # Only emit the new packet, not the full stats
        socketio.emit('new_packet', packet_info)

def start_sniffing():
    """Target function for the sniffer thread"""
    print("Sniffer thread started...")
    # The stop_filter will check the event state
    sniff(prn=packet_callback, store=False, stop_filter=lambda x: stop_event.is_set())
    print("Sniffer thread stopped.")

def send_stats_loop():
    """Target function for the stats update thread"""
    print("Stats thread started...")
    while not stop_event.is_set():
        try:
            # Send stats every 1 second
            socketio.emit('stats_update', get_stats())
            socketio.sleep(1) # Use socketio.sleep for compatibility
        except Exception as e:
            print(f"Error in stats loop: {e}")
            break
    print("Stats thread stopped.")

def get_stats():
    """Helper function to format stats for the frontend"""
    top_ips = sorted(traffic_stats['ips'].items(), key=lambda x: x[1], reverse=True)[:10]
    return {
        'total_packets': traffic_stats['total_packets'],
        'protocols': dict(traffic_stats['protocols']),
        'top_ips': [{'ip': ip, 'count': count} for ip, count in top_ips]
    }

@app.route('/')
def index():
    # Use index.html from your provided code
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    print("Client connected")
    emit('stats_update', get_stats()) # Send current stats on connect

@socketio.on('start_capture')
def handle_start():
    global sniffer_thread, stats_thread, stop_event
    if sniffer_thread is None or not sniffer_thread.is_alive():
        print("Starting capture...")
        stop_event.clear()
        
        # Start the sniffer thread
        sniffer_thread = Thread(target=start_sniffing, daemon=True)
        sniffer_thread.start()
        
        # Start the stats update thread
        stats_thread = Thread(target=send_stats_loop, daemon=True)
        stats_thread.start()
        
        emit('capture_status', {'status': 'started'})

@socketio.on('stop_capture')
def handle_stop():
    global stop_event
    if not stop_event.is_set():
        print("Stopping capture...")
        stop_event.set() # Signal threads to stop
        
        # Wait briefly for threads to see the event
        socketio.sleep(0.1) 
        
    emit('capture_status', {'status': 'stopped'})

@socketio.on('clear_data')
def handle_clear():
    global traffic_stats
    print("Clearing data...")
    traffic_stats = {
        'total_packets': 0,
        'protocols': defaultdict(int),
        'ips': defaultdict(int),
        'recent_packets': []
    }
    # Send cleared stats to all clients
    socketio.emit('stats_update', get_stats(), broadcast=True)
    # Also clear the table on the frontend
    socketio.emit('clear_table', broadcast=True)

if __name__ == '__main__':
    print("Starting Flask-SocketIO server on http://0.0.0.0:5000")
    print("WARNING: Make sure to run this script as an administrator or with sudo!")
    socketio.run(app, debug=True, host='0.0.0.0', port=5000) # <-- FIXED