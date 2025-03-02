#!/usr/bin/env python3
import socket
import select
import threading
import ssl
import argparse
import struct
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('vsock_proxy')

# Constants for VSock
VMADDR_CID_ANY = 0xFFFFFFFF
VMADDR_PORT_ANY = 0xFFFFFFFF
VSOCK_PROTO_TYPE = 40

class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class VSockClient:
    def __init__(self, cid, port):
        self.cid = cid
        self.port = port

    def connect(self):
        """Connect to the VSock server outside the VM"""
        try:
            # Create a VSock socket
            sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            sock.connect((self.cid, self.port))
            return sock
        except Exception as e:
            logger.error(f"VSock connection error: {e}")
            raise

    def send_request(self, method, url, headers, body=None):
        """Send HTTP request over VSock to the host"""
        sock = self.connect()
        try:
            # Prepare request packet
            # Format: [request_type][method_len][url_len][headers_len][body_len][method][url][headers][body]
            method_bytes = method.encode('utf-8')
            url_bytes = url.encode('utf-8')
            
            # Convert headers dict to string and encode
            headers_str = '\r\n'.join(f'{k}: {v}' for k, v in headers.items())
            headers_bytes = headers_str.encode('utf-8')
            
            body_bytes = body if body else b''
            
            # Create packet structure - including request type (0 for HTTP request)
            header = struct.pack('!IIIII', 
                               0,  # Request type 0 for HTTP
                               len(method_bytes),
                               len(url_bytes),
                               len(headers_bytes),
                               len(body_bytes))
            
            # Send header and data
            sock.sendall(header)
            sock.sendall(method_bytes)
            sock.sendall(url_bytes)
            sock.sendall(headers_bytes)
            if body_bytes:
                sock.sendall(body_bytes)
            
            # Read response header (16 bytes)
            response_header = self._recvall(sock, 16)
            if not response_header or len(response_header) < 16:
                raise Exception("Invalid response header received")
                
            status_code, headers_len, body_len = struct.unpack('!III4x', response_header)
            
            # Read response headers
            response_headers_bytes = self._recvall(sock, headers_len)
            if not response_headers_bytes:
                raise Exception("Failed to receive response headers")
                
            response_headers = response_headers_bytes.decode('utf-8', errors='replace')
            
            # Read response body
            response_body = self._recvall(sock, body_len)
            if body_len > 0 and not response_body:
                raise Exception("Failed to receive response body")
            
            return status_code, response_headers, response_body
        
        except Exception as e:
            logger.error(f"Error in send_request: {e}")
            raise
        finally:
            sock.close()
    
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

class ProxyHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, vsock_client=None, **kwargs):
        self.vsock_client = vsock_client
        super().__init__(*args, **kwargs)
    
    def do_METHOD(self):
        method = self.command
        
        # Extract URL and path
        host = self.headers.get('Host')
        if not host:
            self.send_error(400, "Missing Host header")
            return
            
        # Determine if HTTPS or HTTP
        is_connect = (method == 'CONNECT')
        
        if is_connect:
            self._handle_connect()
        else:
            self._handle_regular_request(method)
    
    def _handle_regular_request(self, method):
        # Get request URL
        url = self.path
        if not url.startswith(('http://', 'https://')):
            if 'Host' in self.headers:
                url = f"http://{self.headers['Host']}{url}"
            else:
                self.send_error(400, "Invalid URL")
                return
        
        # Read request body if present
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else None
        
        try:
            # Send request through VSock
            status_code, response_headers_str, response_body = self.vsock_client.send_request(
                method, url, dict(self.headers), body
            )
            
            # Send response back to client
            self.send_response(status_code)
            
            # Parse and set headers
            for header_line in response_headers_str.splitlines():
                if ': ' in header_line:
                    header_name, header_value = header_line.split(': ', 1)
                    self.send_header(header_name, header_value)
            
            self.end_headers()
            
            # Send body
            if response_body:
                self.wfile.write(response_body)
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            self.send_error(502, f"Proxy Error: {str(e)}")
    
    def _handle_connect(self):
        host, port = self.path.split(':', 1)
        port = int(port)
        
        try:
            # Signal to the client that tunnel is established
            self.send_response(200, 'Connection Established')
            self.end_headers()
            
            # Set up a direct tunnel over VSock
            self._tunnel_over_vsock(host, port)
        except Exception as e:
            logger.error(f"CONNECT error: {e}")
            if not self.wfile.closed:
                self.send_error(502, f"CONNECT Error: {str(e)}")
    
    def _tunnel_over_vsock(self, host, port):
        # Create a special VSock socket for tunneling HTTPS
        vsock = self.vsock_client.connect()
        
        try:
            # Send tunnel request (type 1 for tunnel)
            tunnel_req = struct.pack('!I', 1)  # 1 indicates tunnel mode
            host_bytes = host.encode('utf-8')
            tunnel_req += struct.pack('!II', len(host_bytes), port)
            tunnel_req += host_bytes
            
            vsock.sendall(tunnel_req)
            
            # Get socket objects from the request
            client_socket = self.connection
            
            # Set non-blocking mode to use select
            vsock.setblocking(0)
            client_socket.setblocking(0)
            
            # Start tunneling in both directions
            is_active = True
            while is_active:
                # Wait for data on either socket
                read_sockets, _, error_sockets = select.select([client_socket, vsock], [], [client_socket, vsock], 60)
                
                if error_sockets:
                    logger.error("Socket error in tunnel")
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
                            vsock.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except Exception as e:
                        logger.error(f"Tunnel error: {e}")
                        is_active = False
                        break
        except Exception as e:
            logger.error(f"Tunnel setup error: {e}")
        finally:
            # Clean up
            try:
                vsock.close()
            except:
                pass
    
    # Handle all HTTP methods
    do_GET = do_METHOD
    do_POST = do_METHOD
    do_PUT = do_METHOD
    do_DELETE = do_METHOD
    do_HEAD = do_METHOD
    do_OPTIONS = do_METHOD
    do_CONNECT = do_METHOD

    # Override log_message to use our logger
    def log_message(self, format, *args):
        logger.info("%s - - [%s] %s" % (self.client_address[0], self.log_date_time_string(), format % args))

def create_proxy_handler(vsock_client):
    """Create a proxy handler class with the provided VSock client"""
    class CustomProxyHandler(ProxyHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, vsock_client=vsock_client, **kwargs)
    return CustomProxyHandler

def main():
    parser = argparse.ArgumentParser(description='VSock HTTP/HTTPS Proxy')
    parser.add_argument('--host', default='', help='Bind address')
    parser.add_argument('--port', type=int, default=8080, help='Proxy port')
    parser.add_argument('--cid', type=int, default=2, help='CID of the host')
    parser.add_argument('--vsock-port', type=int, default=5000, help='VSock port on the host')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    
    # Create VSock client
    vsock_client = VSockClient(args.cid, args.vsock_port)
    
    # Create custom handler with VSock client
    handler_class = create_proxy_handler(vsock_client)
    
    # Create server
    server = ThreadingHTTPServer((args.host, args.port), handler_class)
    
    logger.info(f"Starting proxy server on {args.host}:{args.port}, connecting to CID {args.cid} on port {args.vsock_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down proxy server")
        server.server_close()

if __name__ == "__main__":
    main()