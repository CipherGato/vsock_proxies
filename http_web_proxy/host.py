#!/usr/bin/env python3
import socket
import struct
import threading
import argparse
import logging
import requests
import select
from urllib.parse import urlparse
import ssl

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('vsock_host_forwarder')

# Constants for VSock
VMADDR_CID_ANY = 0xFFFFFFFF
VMADDR_PORT_ANY = 0xFFFFFFFF

class VSockServer:
    def __init__(self, port, cid=VMADDR_CID_ANY):
        self.port = port
        self.cid = cid
        self.server_socket = None
    
    def start(self):
        """Start VSock server to receive connections from the guest VM"""
        try:
            # Create VSock server socket
            self.server_socket = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self.server_socket.bind((self.cid, self.port))
            self.server_socket.listen(5)
            
            logger.info(f"VSock server listening on port {self.port}")
            
            while True:
                client_socket, client_addr = self.server_socket.accept()
                logger.debug(f"New connection from CID: {client_addr[0]}")
                # Handle each connection in a separate thread
                threading.Thread(target=self.handle_client, args=(client_socket,), daemon=True).start()
                
        except Exception as e:
            logger.error(f"VSock server error: {e}")
            if self.server_socket:
                self.server_socket.close()
    
    def handle_client(self, client_socket):
        """Handle client connection"""
        try:
            # First 4 bytes indicate request type
            req_type_data = client_socket.recv(4)
            if not req_type_data or len(req_type_data) < 4:
                logger.error("Invalid request type received")
                return
                
            req_type = struct.unpack('!I', req_type_data)[0]
            
            if req_type == 1:  # HTTPS tunnel mode
                self._handle_https_tunnel(client_socket)
            else:  # Regular HTTP request mode (type 0)
                self._handle_http_request(client_socket)
                
        except Exception as e:
            logger.error(f"Error handling client: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def _handle_http_request(self, client_socket):
        """Handle HTTP request forwarding"""
        try:
            # Read request header (16 bytes for the sizes)
            header_data = client_socket.recv(16)
            if not header_data or len(header_data) < 16:
                logger.error(f"Invalid header data received, got {len(header_data) if header_data else 0} bytes")
                return
                
            method_len, url_len, headers_len, body_len = struct.unpack('!IIII', header_data)
            
            logger.debug(f"Processing request: method_len={method_len}, url_len={url_len}, headers_len={headers_len}, body_len={body_len}")
            
            # Read method
            method = self._recvall(client_socket, method_len)
            if not method:
                logger.error("Failed to receive method")
                return
            method = method.decode('utf-8')
            
            # Read URL
            url = self._recvall(client_socket, url_len)
            if not url:
                logger.error("Failed to receive URL")
                return
            url = url.decode('utf-8')
            
            # Read headers
            headers_bytes = self._recvall(client_socket, headers_len)
            if not headers_bytes:
                logger.error("Failed to receive headers")
                return
            headers_str = headers_bytes.decode('utf-8')
            
            # Read body if present
            body = None
            if body_len > 0:
                body = self._recvall(client_socket, body_len)
                if not body:
                    logger.error("Failed to receive body")
                    return
            
            # Parse headers into dictionary
            headers = {}
            for line in headers_str.splitlines():
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key] = value
            
            # Make the HTTP request
            logger.debug(f"Forwarding {method} request to {url}")
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    stream=False,  # Get the full response for simplicity
                    allow_redirects=False,  # Let the client handle redirects
                    timeout=30  # Set a reasonable timeout
                )
                
                # Prepare response headers
                response_headers_str = '\r\n'.join(f'{k}: {v}' for k, v in response.headers.items())
                response_headers_bytes = response_headers_str.encode('utf-8')
                
                # Get response body
                response_body = response.content
                
                # Send response header
                response_header = struct.pack('!III4x', 
                                            response.status_code,
                                            len(response_headers_bytes),
                                            len(response_body))
                client_socket.sendall(response_header)
                
                # Send response headers and body
                client_socket.sendall(response_headers_bytes)
                client_socket.sendall(response_body)
                
                logger.debug(f"Response sent: status={response.status_code}, headers_len={len(response_headers_bytes)}, body_len={len(response_body)}")
                
            except requests.RequestException as req_e:
                logger.error(f"Request error: {req_e}")
                self._send_error_response(client_socket, f"Request error: {str(req_e)}")
                
        except Exception as e:
            logger.error(f"HTTP request handling error: {e}")
            self._send_error_response(client_socket, f"Error: {str(e)}")
    
    def _send_error_response(self, client_socket, error_message):
        """Send an error response back to the client"""
        try:
            error_msg = error_message.encode('utf-8')
            error_headers = "Content-Type: text/plain\r\nConnection: close".encode('utf-8')
            
            response_header = struct.pack('!III4x', 
                                        502,  # Bad Gateway
                                        len(error_headers),
                                        len(error_msg))
            
            client_socket.sendall(response_header)
            client_socket.sendall(error_headers)
            client_socket.sendall(error_msg)
        except Exception as e:
            logger.error(f"Failed to send error response: {e}")
    
    def _handle_https_tunnel(self, client_socket):
        """Handle HTTPS tunneling"""
        try:
            # Read host and port data
            header_data = client_socket.recv(8)
            if not header_data or len(header_data) < 8:
                logger.error("Invalid tunnel header received")
                return
                
            host_len, port = struct.unpack('!II', header_data)
            
            # Read host
            host_data = self._recvall(client_socket, host_len)
            if not host_data:
                logger.error("Failed to receive host")
                return
            
            host = host_data.decode('utf-8')
            
            logger.debug(f"Establishing HTTPS tunnel to {host}:{port}")
            
            # Connect to the target host
            target_socket = None
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(10)  # Set a timeout for the connection
                target_socket.connect((host, port))
                target_socket.settimeout(None)  # Reset timeout for data transfer
            except socket.error as sock_err:
                logger.error(f"Failed to connect to {host}:{port}: {sock_err}")
                return
            
            # Set non-blocking mode
            client_socket.setblocking(0)
            target_socket.setblocking(0)
            
            # Start tunneling in both directions
            is_active = True
            while is_active:
                # Wait for data on either socket
                try:
                    read_sockets, _, error_sockets = select.select(
                        [client_socket, target_socket], 
                        [], 
                        [client_socket, target_socket], 
                        60
                    )
                    
                    if error_sockets:
                        logger.debug("Socket error detected")
                        is_active = False
                        break
                        
                    if not read_sockets:  # Timeout
                        continue
                        
                    for sock in read_sockets:
                        try:
                            data = sock.recv(8192)
                            if not data:
                                logger.debug("Connection closed by peer")
                                is_active = False
                                break
                                
                            # Forward data to the other side
                            if sock == client_socket:
                                target_socket.sendall(data)
                            else:
                                client_socket.sendall(data)
                        except Exception as e:
                            logger.error(f"Data forwarding error: {e}")
                            is_active = False
                            break
                except Exception as select_err:
                    logger.error(f"Select error: {select_err}")
                    is_active = False
            
            # Clean up
            if target_socket:
                try:
                    target_socket.close()
                except:
                    pass
            
        except Exception as e:
            logger.error(f"HTTPS tunnel error: {e}")
    
    def _recvall(self, sock, n):
        """Helper function to receive n bytes or return None if EOF is hit"""
        if n == 0:
            return b''
            
        data = bytearray()
        sock.settimeout(30)  # Set a timeout to prevent hanging
        
        try:
            while len(data) < n:
                packet = sock.recv(min(8192, n - len(data)))
                if not packet:
                    logger.error(f"Connection closed while receiving data. Got {len(data)} of {n} bytes")
                    return None
                data.extend(packet)
            return data
        except socket.timeout:
            logger.error(f"Socket timeout while receiving data. Got {len(data)} of {n} bytes")
            return None
        except Exception as e:
            logger.error(f"Error receiving data: {e}")
            return None

def main():
    parser = argparse.ArgumentParser(description='VSock Host Forwarder')
    parser.add_argument('--port', type=int, default=5000, help='VSock port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Create and start VSock server
    server = VSockServer(args.port)
    server.start()

if __name__ == "__main__":
    main()