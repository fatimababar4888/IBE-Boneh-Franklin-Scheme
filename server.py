"""
IBE (Identity-Based Encryption) Server Module with GUI.
"""

import os
import pickle
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Dict, List, Any, Optional

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC


class IBEServer:
    """Server implementation for Boneh-Franklin IBE scheme."""
    
    def __init__(self, host: str = 'localhost', port: int = 12345, debug: bool = False):
        self.master_private_key = ECC.generate(curve='P-256')
        self.master_public_key = self.master_private_key.public_key()
        self.host = host
        self.port = port
        self.sock: Optional[socket.socket] = None
        self.running = False
        self.debug = debug
        self.key_extraction_times: List[float] = []
        self.connected_clients = []  # Will store dicts with address, identity and last_seen info
        self.log_messages = []
    
    def extract_private_key(self, identity: str) -> int:
        """Extract a private key for a given identity."""
        start_time = time.time()
        
        identity_hash = SHA256.new(identity.encode()).digest()
        identity_int = int.from_bytes(identity_hash, byteorder='big')

        curve_order = ECC._curves['P-256'].order
        identity_private_key = (self.master_private_key.d * identity_int) % curve_order
        
        duration = time.time() - start_time
        self.key_extraction_times.append(duration)
        
        return identity_private_key
    
    def handle_client(self, client_socket: socket.socket, address: tuple) -> None:
        """Handle communication with a client."""
        # Add client to connected clients list with identity info
        client_info = {"address": address, "identity": "Unknown", "last_seen": time.time()}
        self.connected_clients.append(client_info)
        
        try:
            client_socket.settimeout(30.0)
            data = client_socket.recv(4096)
            if not data:
                return
                
            request = pickle.loads(data)
            request_type = request.get('type')
            
            # Update client identity if this is an extract_key request
            if request_type == 'extract_key' and request.get('identity'):
                for client in self.connected_clients:
                    if client["address"] == address:
                        client["identity"] = request.get('identity')
                        client["last_seen"] = time.time()
                        break
            
            if request_type == 'get_public_key':
                x = self.master_public_key._point.x
                y = self.master_public_key._point.y
                
                response = {
                    'status': 'success',
                    'x': x,
                    'y': y
                }
                client_socket.send(pickle.dumps(response))
                
            elif request_type == 'extract_key':
                identity = request.get('identity')
                if identity:
                    private_key = self.extract_private_key(identity)
                    response = {
                        'status': 'success',
                        'private_key': private_key
                    }
                else:
                    response = {
                        'status': 'error',
                        'message': 'Identity not provided'
                    }
                client_socket.send(pickle.dumps(response))
                
            else:
                response = {
                    'status': 'error',
                    'message': 'Unknown request type'
                }
                client_socket.send(pickle.dumps(response))
                
        except socket.timeout:
            response = {
                'status': 'error',
                'message': 'Connection timed out'
            }
            client_socket.send(pickle.dumps(response))
        except Exception as e:
            response = {
                'status': 'error',
                'message': str(e)
            }
            client_socket.send(pickle.dumps(response))
        finally:
            client_socket.close()
            # Remove client from connected clients list
            for i, client in enumerate(self.connected_clients):
                if client["address"] == address:
                    self.connected_clients.pop(i)
                    break
    
    def start(self) -> None:
        """Start the IBE server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(5)
            self.running = True
            
            while self.running:
                try:
                    self.sock.settimeout(1.0)
                    client_sock, address = self.sock.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_sock, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
        except OSError as e:
            print(f"Server error: {e}")
            raise
        finally:
            self.stop()
    
    def stop(self) -> None:
        """Stop the IBE server."""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception as e:
                print(f"Error closing socket: {e}")
    
    def print_performance_stats(self) -> None:
        """Print performance statistics."""
        if not self.key_extraction_times:
            print("No key extraction operations performed yet.")
            return
            
        avg_time = sum(self.key_extraction_times) / len(self.key_extraction_times)
        print(f"\nPerformance Statistics:")
        print(f"Total key extractions: {len(self.key_extraction_times)}")
        print(f"Average key extraction time: {avg_time:.6f} seconds")
        print(f"Min extraction time: {min(self.key_extraction_times):.6f} seconds")
        print(f"Max extraction time: {max(self.key_extraction_times):.6f} seconds")


class IBEServerGUI:
    """GUI for the IBE Server."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("IBE Server")
        self.server = None
        self.server_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Server settings
        ttk.Label(main_frame, text="Server Host:").grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(main_frame, width=30)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="Server Port:").grid(row=1, column=0, sticky=tk.W)
        self.port_entry = ttk.Entry(main_frame, width=30)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        # Server control buttons
        self.start_btn = ttk.Button(main_frame, text="Start Server", command=self.start_server)
        self.start_btn.grid(row=2, column=0, pady=5)
        
        self.stop_btn = ttk.Button(main_frame, text="Stop Server", command=self.stop_server, state="disabled")
        self.stop_btn.grid(row=2, column=1, pady=5)
        
        # Status indicator
        status_frame = ttk.LabelFrame(main_frame, text="Server Status")
        status_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.status_var = tk.StringVar(value="Server Stopped")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(pady=5)
        
        # Tab control
        self.tab_control = ttk.Notebook(main_frame)
        self.tab_control.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Logs tab
        self.logs_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.logs_tab, text="Server Logs")
        self.setup_logs_tab()
        
        # Clients tab
        self.clients_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.clients_tab, text="Connected Clients")
        self.setup_clients_tab()
        
        # Stats tab
        self.stats_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.stats_tab, text="Statistics")
        self.setup_stats_tab()
        
        # Make grid expandable
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # Start periodic updates
        self.update_ui()
    
    def setup_logs_tab(self):
        """Setup the logs tab."""
        self.logs_text = scrolledtext.ScrolledText(self.logs_tab, width=60, height=15)
        self.logs_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.logs_text.insert(tk.END, "Server logs will appear here...\n")
        self.logs_text.config(state="disabled")
        
        clear_btn = ttk.Button(self.logs_tab, text="Clear Logs", command=self.clear_logs)
        clear_btn.pack(pady=5)
    
    def setup_clients_tab(self):
        """Setup the clients tab."""
        self.clients_listbox = tk.Listbox(self.clients_tab, width=60, height=15)
        self.clients_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(self.clients_tab, orient="vertical", command=self.clients_listbox.yview)
        scrollbar.place(relx=1.0, rely=0, relheight=1.0, anchor="ne")
        self.clients_listbox.config(yscrollcommand=scrollbar.set)
    
    def setup_stats_tab(self):
        """Setup the statistics tab."""
        self.stats_text = scrolledtext.ScrolledText(self.stats_tab, width=60, height=15)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.stats_text.insert(tk.END, "Statistics will appear here...\n")
        self.stats_text.config(state="disabled")
        
        refresh_btn = ttk.Button(self.stats_tab, text="Refresh Statistics", command=self.refresh_stats)
        refresh_btn.pack(pady=5)
    
    def start_server(self):
        """Start the IBE server."""
        host = self.host_entry.get()
        port = self.port_entry.get()
        
        try:
            port = int(port)
        except ValueError:
            self.log("Invalid port number")
            return
        
        # Create a new server instance
        self.server = IBEServer(host, port)
        
        # Add a reference to the logging function
        original_handle_client = self.server.handle_client
        
        def handle_client_with_logging(client_socket, address):
            self.log(f"New client connection from {address[0]}:{address[1]}")
            result = original_handle_client(client_socket, address)
            return result
            
        self.server.handle_client = handle_client_with_logging
        
        # Start the server in a separate thread
        self.server_thread = threading.Thread(target=self.server.start)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        self.status_var.set(f"Server Running ({host}:{port})")
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.log(f"Server started on {host}:{port}")
    
    def stop_server(self):
        """Stop the IBE server."""
        if self.server:
            self.server.stop()
            self.status_var.set("Server Stopped")
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")
            self.log("Server stopped")
    
    def update_ui(self):
        """Update UI components periodically."""
        if self.server and self.server.running:
            # Update connected clients
            self.clients_listbox.delete(0, tk.END)
            for i, client in enumerate(self.server.connected_clients):
                address = client["address"]
                identity = client["identity"]
                last_seen = time.strftime("%H:%M:%S", time.localtime(client["last_seen"]))
                self.clients_listbox.insert(tk.END, f"{i+1}. {identity} ({address[0]}:{address[1]}) - Last seen: {last_seen}")
                
            # Add this log message to check clients list
            if self.server.connected_clients:
                self.log(f"Active clients: {len(self.server.connected_clients)}")
        
        # Schedule next update
        self.root.after(1000, self.update_ui)
    
    def log(self, message: str):
        """Add a message to the logs."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_msg = f"[{timestamp}] {message}\n"
        
        # Print to console for debugging
        print(log_msg.strip())
        
        # Add to server logs if server exists
        if hasattr(self, 'server') and self.server:
            self.server.log_messages.append(log_msg)
        
        # Update the GUI
        self.logs_text.config(state="normal")
        self.logs_text.insert(tk.END, log_msg)
        self.logs_text.see(tk.END)
        self.logs_text.config(state="disabled")
    
    def clear_logs(self):
        """Clear the logs."""
        self.logs_text.config(state="normal")
        self.logs_text.delete("1.0", tk.END)
        self.logs_text.config(state="disabled")
    
    def refresh_stats(self):
        """Refresh the statistics display."""
        if not self.server:
            return
        
        self.server.print_performance_stats()
        
        stats_text = "Performance Statistics:\n\n"
        
        if not self.server.key_extraction_times:
            stats_text += "No key extraction operations performed yet."
        else:
            avg_time = sum(self.server.key_extraction_times) / len(self.server.key_extraction_times)
            stats_text += f"Total key extractions: {len(self.server.key_extraction_times)}\n"
            stats_text += f"Average key extraction time: {avg_time:.6f} seconds\n"
            stats_text += f"Min extraction time: {min(self.server.key_extraction_times):.6f} seconds\n"
            stats_text += f"Max extraction time: {max(self.server.key_extraction_times):.6f} seconds\n"
        
        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", stats_text)
        self.stats_text.config(state="disabled")


def main():
    """Main function to run the GUI."""
    root = tk.Tk()
    root.geometry("700x500")
    app = IBEServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()