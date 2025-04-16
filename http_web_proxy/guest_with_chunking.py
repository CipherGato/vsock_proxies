#!/usr/bin/env python3
"""
Enhanced HTTP vsock proxy with chunked encoding support
Based on https://github.com/CipherGato/vsock_proxies/tree/main/http_web_proxy
"""

import socket
import threading
import argparse
import signal
import sys
import re
import binascii

# Constants
BUFFER_SIZE = 8192
DEFAULT_LISTEN_PORT = 8080
DEFAULT_VSOCK_PORT = 80
DEFAULT_CID = 2

# Check if vsock is available
try:
    import socket
    AF_VSOCK = getattr(socket, 'AF_VSOCK', 40)
    has_vsock = True
except (ImportError, AttributeError):
    has_vsock = False
    print("Warning: vsock module not available, falling back to AF_VSOCK=40")
    AF_VSOCK = 40


def connect_to_vsock(cid, port):
    """Connect to a vsock service"""
    try:
        sock = socket.socket(AF_VSOCK, socket.SOCK_STREAM)
        sock.connect((cid, port))
        return sock
    except Exception as e:
        print(f"Failed to connect to vsock cid={cid}, port={port}: {e}")
        return None


def is_chunked_response(headers):
    """Check if the response uses chunked encoding"""
    transfer_encoding = re.search(r'Transfer-Encoding:\s*(.*?)(?:\r\n|\n)', headers, re.IGNORECASE)
    if transfer_encoding and 'chunked' in transfer_encoding.group(1).lower():
        return True
    return False


def find_header_end(data):
    """Find the end of HTTP headers and return (headers, body)"""
    # Look for double CRLF or double LF
    header_end = data.find(b'\r\n\r\n')
    if header_end == -1:
        header_end = data.find(b'\n\n')
        if header_end == -1:
            return data, b''  # Headers not complete
        header_end += 2  # Double LF
    else:
        header_end += 4  # Double CRLF
    
    headers = data[:header_end]
    body = data[header_end:]
    return headers, body


def handle_chunked_response(vsock_conn, client_conn, initial_body=b''):
    """Handle a chunked HTTP response"""
    # Buffer for processing chunks
    buffer = bytearray(initial_body)
    
    # Main chunked processing loop
    while True:
        # If buffer is empty or we need more data, read from vsock
        if not buffer:
            data = vsock_conn.recv(BUFFER_SIZE)
            if not data:
                break  # Connection closed
            buffer.extend(data)
        
        # Process chunks from the buffer
        # First, try to find the chunk size
        chunk_size_end = buffer.find(b'\r\n')
        if chunk_size_end == -1:
            # Need more data to find chunk size
            data = vsock_conn.recv(BUFFER_SIZE)
            if not data:
                # Incomplete chunk, forward what we have and exit
                if buffer:
                    client_conn.sendall(bytes(buffer))
                break
            buffer.extend(data)
            continue
        
        # Extract and parse chunk size (hex string)
        try:
            chunk_size_str = buffer[:chunk_size_end].decode('ascii').split(';')[0].strip()
            chunk_size = int(chunk_size_str, 16)
        except (ValueError, UnicodeDecodeError) as e:
            print(f"Error parsing chunk size: {e}")
            # Forward buffer as-is and continue
            client_conn.sendall(bytes(buffer))
            buffer.clear()
            continue
        
        # Check if this is the last chunk (size 0)
        if chunk_size == 0:
            # Last chunk - forward everything we have plus any trailers
            client_conn.sendall(bytes(buffer))
            # Read and forward any remaining data (trailers)
            while True:
                data = vsock_conn.recv(BUFFER_SIZE)
                if not data:
                    break
                client_conn.sendall(data)
            break
        
        # Calculate the total size of this chunk including size line, data, and trailing CRLF
        total_chunk_size = chunk_size_end + 2 + chunk_size + 2
        
        # If we don't have the full chunk yet, get more data
        if len(buffer) < total_chunk_size:
            # Forward what we have so far
            client_conn.sendall(bytes(buffer))
            buffer.clear()
            
            # We need to read more data to complete this chunk
            remaining = total_chunk_size - len(buffer)
            while remaining > 0:
                data = vsock_conn.recv(min(BUFFER_SIZE, remaining))
                if not data:
                    break  # Connection closed
                client_conn.sendall(data)
                remaining -= len(data)
            
            # If we didn't get all data, exit
            if remaining > 0:
                break
        else:
            # We have the full chunk, forward it
            chunk_to_send = buffer[:total_chunk_size]
            client_conn.sendall(bytes(chunk_to_send))
            # Remove the processed chunk from buffer
            del buffer[:total_chunk_size]


def handle_client(client_conn, client_addr, dest_cid, dest_port):
    """Handle a client HTTP connection"""
    print(f"New connection from {client_addr}")
    
    # Connect to vsock service
    vsock_conn = connect_to_vsock(dest_cid, dest_port)
    if not vsock_conn:
        client_conn.close()
        return
    
    try:
        # Forward the HTTP request
        request = client_conn.recv(BUFFER_SIZE)
        if not request:
            return
        
        vsock_conn.sendall(request)
        
        # Get the HTTP response headers
        response_data = bytearray()
        headers_complete = False
        headers = None
        body = None
        
        # Read until we have the complete headers
        while not headers_complete:
            data = vsock_conn.recv(BUFFER_SIZE)
            if not data:
                break
            
            response_data.extend(data)
            headers, body = find_header_end(response_data)
            
            if body:  # We found the end of headers
                headers_complete = True
        
        # If we couldn't get complete headers, just forward what we have
        if not headers_complete:
            if response_data:
                client_conn.sendall(response_data)
            return
        
        # Forward the headers to the client
        client_conn.sendall(headers)
        
        # Check if response is chunked
        headers_str = headers.decode('latin1')  # Use latin1 to avoid decoding errors
        chunked = is_chunked_response(headers_str)
        
        if chunked:
            # Forward initial body data and handle chunked response
            if body:
                handle_chunked_response(vsock_conn, client_conn, body)
            else:
                handle_chunked_response(vsock_conn, client_conn)
        else:
            # For non-chunked responses, forward the body and remaining data
            if body:
                client_conn.sendall(body)
            
            # Forward remaining data
            while True:
                data = vsock_conn.recv(BUFFER_SIZE)
                if not data:
                    break
                client_conn.sendall(data)
    
    except Exception as e:
        print(f"Error handling client: {e}")
    
    finally:
        vsock_conn.close()
        client_conn.close()
        print(f"Connection with {client_addr} closed")


def signal_handler(sig, frame):
    """Handle interrupt signals"""
    print('Exiting...')
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='HTTP vsock proxy with chunked encoding support')
    parser.add_argument('-p', '--port', type=int, default=DEFAULT_LISTEN_PORT,
                        help=f'Port to listen on (default: {DEFAULT_LISTEN_PORT})')
    parser.add_argument('-c', '--cid', type=int, default=DEFAULT_CID,
                        help=f'Destination CID (default: {DEFAULT_CID})')
    parser.add_argument('-P', '--vsock-port', type=int, default=DEFAULT_VSOCK_PORT,
                        help=f'Destination vsock port (default: {DEFAULT_VSOCK_PORT})')
    
    args = parser.parse_args()
    
    # Set up signal handling
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', args.port))
        server.listen(5)
        print(f"HTTP vsock proxy listening on port {args.port}, forwarding to cid={args.cid} port={args.vsock_port}")
        
        while True:
            client_conn, client_addr = server.accept()
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_conn, client_addr, args.cid, args.vsock_port)
            )
            client_thread.daemon = True
            client_thread.start()
    
    except Exception as e:
        print(f"Server error: {e}")
    
    finally:
        server.close()


if __name__ == "__main__":
    main()
