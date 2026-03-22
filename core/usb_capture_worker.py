"""Eigenstaendiger USB-Kamera Capture-Prozess.

Wird als separates Python-Skript via subprocess.Popen gestartet.
Liest Frames von V4L2 und sendet sie ueber Unix Domain Socket
an den LiveCapture Hauptprozess.

Protokoll (ueber Socket):
  'S' + JSON info     → started + Kamera-Info
  'I' + JSON info     → Stream-Info Update
  'F' + 4B len + JPEG → Frame (JPEG-komprimiert fuer Performance)
  'E' + text           → Error
"""

import cv2
import json
import socket
import struct
import sys
import time


def main():
    if len(sys.argv) < 3:
        print("Usage: usb_capture_worker.py <source> <socket_path>",
              file=sys.stderr)
        sys.exit(1)

    source = sys.argv[1]
    sock_path = sys.argv[2]

    # V4L2 oeffnen
    src = source.strip()
    if src.startswith('/dev/video'):
        idx = int(src.replace('/dev/video', ''))
        cap = cv2.VideoCapture(idx, cv2.CAP_V4L2)
        cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        backend = "V4L2"
    elif '://' in src:
        cap = cv2.VideoCapture(src, cv2.CAP_FFMPEG)
        backend = "Stream"
    else:
        try:
            idx = int(src)
            cap = cv2.VideoCapture(idx, cv2.CAP_V4L2)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
            backend = "V4L2"
        except ValueError:
            # Fehlermeldung ueber Socket senden
            _send_error(sock_path, f"Ungueltige Quelle: {src}")
            sys.exit(1)

    if not cap.isOpened():
        _send_error(sock_path, f"Kann '{src}' nicht oeffnen.")
        if cap:
            cap.release()
        sys.exit(1)

    # Kamera-Parameter lesen
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = cap.get(cv2.CAP_PROP_FPS)
    fourcc_int = int(cap.get(cv2.CAP_PROP_FOURCC))
    fourcc_str = "".join([chr((fourcc_int >> 8 * i) & 0xFF) for i in range(4)])
    codec = f"{backend}/{fourcc_str}" if fourcc_str.strip('\x00') else backend

    # Unix Socket verbinden
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(sock_path)
    except Exception as e:
        print(f"Socket-Verbindung fehlgeschlagen: {e}", file=sys.stderr)
        cap.release()
        sys.exit(1)

    # Started-Nachricht senden
    info = json.dumps({'resolution': f"{w}x{h}", 'fps': f"{fps:.0f}",
                       'codec': codec, 'frames': 0})
    sock.sendall(b'S' + info.encode() + b'\n')

    frame_count = 0
    fps_counter = 0
    fps_last = time.time()
    current_fps = 0.0

    # JPEG-Qualitaet (Kompromiss: Geschwindigkeit vs Qualitaet)
    encode_params = [cv2.IMWRITE_JPEG_QUALITY, 85]

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                continue

            frame_count += 1
            fps_counter += 1

            now = time.time()
            elapsed = now - fps_last
            if elapsed >= 1.0:
                current_fps = fps_counter / elapsed
                fps_counter = 0
                fps_last = now

            # Frame als JPEG komprimieren (15MB raw → ~200KB JPEG)
            ok, jpeg = cv2.imencode('.jpg', frame, encode_params)
            if not ok:
                continue

            jpeg_bytes = jpeg.tobytes()
            # Frame senden: 'F' + 4 Byte Laenge + JPEG-Daten
            try:
                sock.sendall(b'F' + struct.pack('<I', len(jpeg_bytes))
                             + jpeg_bytes)
            except BrokenPipeError:
                break  # Hauptprozess hat Socket geschlossen

            # Info alle 10 Frames
            if frame_count % 10 == 0:
                info = json.dumps({
                    'resolution': f"{frame.shape[1]}x{frame.shape[0]}",
                    'fps': f"{current_fps:.1f}",
                    'codec': codec,
                    'frames': frame_count,
                })
                try:
                    sock.sendall(b'I' + info.encode() + b'\n')
                except BrokenPipeError:
                    break

    except KeyboardInterrupt:
        pass
    finally:
        cap.release()
        sock.close()


def _send_error(sock_path, msg):
    """Fehlermeldung ueber Socket senden."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sock_path)
        sock.sendall(b'E' + msg.encode() + b'\n')
        sock.close()
    except Exception:
        print(f"ERROR: {msg}", file=sys.stderr)


if __name__ == '__main__':
    main()
