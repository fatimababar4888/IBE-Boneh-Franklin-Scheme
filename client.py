"""
IBE (Identity-Based Encryption) Client Module with GUI.
"""

import os
import pickle
import socket
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from typing import Dict, List, Optional, Tuple, Union, Any

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Random import get_random_bytes


class IBEClient:
    """Client implementation for Boneh-Franklin IBE scheme."""
    
    def __init__(self, identity: str, server_host: str = 'localhost', server_port: int = 12345):
        self.identity = identity
        self.server_host = server_host
        self.server_port = server_port
        self.private_key: Optional[int] = None
        self.master_public_key: Optional[EccPoint] = None
        self.messages: List[Tuple[str, Union[str, bytes]]] = []
        self.encryption_times: Dict[int, List[float]] = {}
        self.decryption_times: Dict[int, List[float]] = {}
        self.debug = False
        
        try:
            self._fetch_master_public_key()
        except Exception as e:
            print(f"Warning: Could not connect to server: {e}")
        
    def _fetch_master_public_key(self) -> None:
        """Fetch the master public key from the PKG server."""
        try:
            request = {'type': 'get_public_key'}
            response = self._send_to_server(request)
            
            if response.get('status') == 'success':
                x = response.get('x')
                y = response.get('y')
                curve = 'P-256'
                self.master_public_key = EccPoint(x, y, curve)
        except Exception as e:
            print(f"Error fetching master public key: {e}")
            raise
    
    def _send_to_server(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send data to the PKG server and receive response."""
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.settimeout(10.0)
            client_socket.connect((self.server_host, self.server_port))
            client_socket.send(pickle.dumps(data))
            
            client_socket.settimeout(30.0)
            response_data = client_socket.recv(4096)
            if not response_data:
                raise ConnectionError("Empty response from server")
                
            return pickle.loads(response_data)
        except socket.timeout:
            raise TimeoutError(f"Connection to {self.server_host}:{self.server_port} timed out")
        except socket.error as e:
            raise ConnectionError(f"Socket error: {e}")
        except Exception as e:
            raise ConnectionError(f"Error communicating with server: {e}")
        finally:
            client_socket.close()
    
    def register(self) -> bool:
        """Register with the PKG server to get a private key."""
        if self.private_key is not None:
            return True
            
        try:
            request = {
                'type': 'extract_key',
                'identity': self.identity
            }
            response = self._send_to_server(request)
            
            if response.get('status') == 'success':
                self.private_key = response.get('private_key')
                return True
            else:
                return False
        except Exception as e:
            print(f"Error during registration: {e}")
            return False
    
    def encrypt(self, recipient_identity: str, message: Union[str, bytes]) -> Tuple[bytes, bytes]:
        """Encrypt a message for a specific identity."""
        if self.master_public_key is None:
            raise ValueError("Master public key not available. Cannot encrypt.")
            
        start_time = time.time()
        message_bytes = message.encode('utf-8') if isinstance(message, str) else message
            
        identity_hash = SHA256.new(recipient_identity.encode()).digest()
        identity_int = int.from_bytes(identity_hash, byteorder='big')
        shared_point = self.master_public_key * identity_int
        
        x_bytes = shared_point.x.to_bytes(32, byteorder='big')
        y_bytes = shared_point.y.to_bytes(32, byteorder='big')
        point_bytes = x_bytes + y_bytes
        shared_secret = SHA256.new(point_bytes).digest()

        iv = get_random_bytes(16)
        cipher = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
        
        block_size = 16
        padding_length = block_size - (len(message_bytes) % block_size)
        if padding_length == 0:
            padding_length = block_size
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        ciphertext = cipher.encrypt(padded_message)
        
        duration = time.time() - start_time
        msg_size = len(message_bytes)
        if msg_size not in self.encryption_times:
            self.encryption_times[msg_size] = []
        self.encryption_times[msg_size].append(duration)
        
        return iv, ciphertext
    
    def decrypt(self, sender_identity: str, iv: bytes, ciphertext: bytes) -> Union[str, bytes]:
        """Decrypt a message."""
        if not self.private_key:
            if not self.register():
                raise ValueError("Registration required before decryption.")
        
        start_time = time.time()
        curve = 'P-256'
        G = ECC._curves[curve].G
        shared_point = G * self.private_key
        
        x_bytes = shared_point.x.to_bytes(32, byteorder='big')
        y_bytes = shared_point.y.to_bytes(32, byteorder='big')
        point_bytes = x_bytes + y_bytes
        shared_secret = SHA256.new(point_bytes).digest()

        cipher = AES.new(shared_secret[:16], AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        decrypted_bytes = self._remove_padding(decrypted_padded)
        
        duration = time.time() - start_time
        msg_size = len(ciphertext)
        if msg_size not in self.decryption_times:
            self.decryption_times[msg_size] = []
        self.decryption_times[msg_size].append(duration)
        
        try:
            decrypted_message = decrypted_bytes.decode('utf-8')
        except UnicodeDecodeError:
            decrypted_message = decrypted_bytes
            
        self.messages.append((sender_identity, decrypted_message))
        return decrypted_message
    
    def _remove_padding(self, padded_data: bytes) -> bytes:
        """Remove PKCS#7 padding from decrypted data."""
        if not padded_data:
            return padded_data
            
        padding_length = padded_data[-1]
        if 0 < padding_length <= 16:
            valid_padding = all(b == padding_length for b in padded_data[-padding_length:])
            if valid_padding:
                return padded_data[:-padding_length]
        return padded_data
    
    def send_message(self, recipient_identity: str, message: Union[str, bytes]) -> Tuple[bytes, bytes]:
        """Send an encrypted message to another user."""
        return self.encrypt(recipient_identity, message)
    
    def receive_message(self, sender_identity: str, iv: bytes, ciphertext: bytes) -> Union[str, bytes]:
        """Receive and decrypt a message."""
        return self.decrypt(sender_identity, iv, ciphertext)
    
    def print_performance_stats(self) -> None:
        """Print performance statistics for this client."""
        print(f"\nPerformance Statistics for {self.identity}:")
        
        if self.encryption_times:
            print("\nEncryption Times:")
            for size, times in sorted(self.encryption_times.items()):
                avg_time = sum(times) / len(times)
                print(f"  Message size {size} bytes: {avg_time:.6f} seconds (avg of {len(times)} operations)")
        
        if self.decryption_times:
            print("\nDecryption Times:")
            for size, times in sorted(self.decryption_times.items()):
                avg_time = sum(times) / len(times)
                print(f"  Message size {size} bytes: {avg_time:.6f} seconds (avg of {len(times)} operations)")


class IBEClientGUI:
    """GUI for the IBE Client."""
    
    def __init__(self, root):
        self.root = root
        self.root.title("IBE Client")
        self.client = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Identity setup
        ttk.Label(main_frame, text="Identity:").grid(row=0, column=0, sticky=tk.W)
        self.identity_entry = ttk.Entry(main_frame, width=30)
        self.identity_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="Server Host:").grid(row=1, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(main_frame, width=30)
        self.host_entry.insert(0, "localhost")
        self.host_entry.grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(main_frame, text="Server Port:").grid(row=2, column=0, sticky=tk.W)
        self.port_entry = ttk.Entry(main_frame, width=30)
        self.port_entry.insert(0, "12345")
        self.port_entry.grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        connect_btn = ttk.Button(main_frame, text="Connect", command=self.connect_client)
        connect_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Tab control
        self.tab_control = ttk.Notebook(main_frame)
        self.tab_control.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E))
        
        # Send tab
        self.send_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.send_tab, text="Send Message")
        self.setup_send_tab()
        
        # Receive tab
        self.receive_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.receive_tab, text="Receive Message")
        self.setup_receive_tab()
        
        # Messages tab
        self.messages_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.messages_tab, text="Messages")
        self.setup_messages_tab()
        
        # Stats tab
        self.stats_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.stats_tab, text="Statistics")
        self.setup_stats_tab()
        
        # Disable tabs until connected
        self.tab_control.tab(1, state="disabled")
        self.tab_control.tab(2, state="disabled")
        self.tab_control.tab(3, state="disabled")
    
    def setup_send_tab(self):
        """Setup the send message tab."""
        ttk.Label(self.send_tab, text="Recipient Identity:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.recipient_entry = ttk.Entry(self.send_tab, width=30)
        self.recipient_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(self.send_tab, text="Message:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.message_text = scrolledtext.ScrolledText(self.send_tab, width=40, height=10)
        self.message_text.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        
        send_btn = ttk.Button(self.send_tab, text="Send", command=self.send_message)
        send_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        ttk.Label(self.send_tab, text="Encrypted Message:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.iv_entry = ttk.Entry(self.send_tab, width=40)
        self.iv_entry.grid(row=5, column=0, columnspan=2, padx=5, pady=5, sticky=(tk.W, tk.E))
        
        self.ciphertext_entry = scrolledtext.ScrolledText(self.send_tab, width=40, height=5)
        self.ciphertext_entry.grid(row=6, column=0, columnspan=2, padx=5, pady=5)
        
        copy_btn = ttk.Button(self.send_tab, text="Copy to Clipboard", command=self.copy_encrypted)
        copy_btn.grid(row=7, column=0, columnspan=2, pady=5)
    
    def setup_receive_tab(self):
        """Setup the receive message tab."""
        ttk.Label(self.receive_tab, text="Sender Identity:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.sender_entry = ttk.Entry(self.receive_tab, width=30)
        self.sender_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(self.receive_tab, text="IV (hex):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.receive_iv_entry = ttk.Entry(self.receive_tab, width=40)
        self.receive_iv_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        ttk.Label(self.receive_tab, text="Ciphertext (hex):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.receive_ciphertext_entry = scrolledtext.ScrolledText(self.receive_tab, width=40, height=5)
        self.receive_ciphertext_entry.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        receive_btn = ttk.Button(self.receive_tab, text="Decrypt", command=self.receive_message)
        receive_btn.grid(row=4, column=0, columnspan=2, pady=5)
        
        ttk.Label(self.receive_tab, text="Decrypted Message:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.decrypted_text = scrolledtext.ScrolledText(self.receive_tab, width=40, height=5, state="disabled")
        self.decrypted_text.grid(row=6, column=0, columnspan=2, padx=5, pady=5)
    
    def setup_messages_tab(self):
        """Setup the messages tab."""
        self.messages_listbox = tk.Listbox(self.messages_tab, width=60, height=15)
        self.messages_listbox.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(self.messages_tab, orient="vertical", command=self.messages_listbox.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.messages_listbox.config(yscrollcommand=scrollbar.set)
        
        view_btn = ttk.Button(self.messages_tab, text="View Message", command=self.view_message)
        view_btn.grid(row=1, column=0, pady=5)
        
        self.message_view = scrolledtext.ScrolledText(self.messages_tab, width=60, height=10, state="disabled")
        self.message_view.grid(row=2, column=0, columnspan=2, padx=5, pady=5)
    
    def setup_stats_tab(self):
        """Setup the statistics tab."""
        self.stats_text = scrolledtext.ScrolledText(self.stats_tab, width=60, height=15, state="disabled")
        self.stats_text.grid(row=0, column=0, padx=5, pady=5, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        refresh_btn = ttk.Button(self.stats_tab, text="Refresh Statistics", command=self.refresh_stats)
        refresh_btn.grid(row=1, column=0, pady=5)
    
    def connect_client(self):
        """Connect the client with the provided identity and server info."""
        identity = self.identity_entry.get()
        host = self.host_entry.get()
        port = self.port_entry.get()
        
        if not identity:
            messagebox.showerror("Error", "Please enter an identity")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Invalid port number")
            return
        
        try:
            self.client = IBEClient(identity, host, port)
            if not self.client.register():
                messagebox.showerror("Error", "Failed to register with server")
                return
            
            # Enable tabs after successful connection
            self.tab_control.tab(1, state="normal")
            self.tab_control.tab(2, state="normal")
            self.tab_control.tab(3, state="normal")
            
            messagebox.showinfo("Success", f"Connected as {identity}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")
    
    def send_message(self):
        """Handle sending a message."""
        if not self.client:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        recipient = self.recipient_entry.get()
        message = self.message_text.get("1.0", tk.END).strip()
        
        if not recipient or not message:
            messagebox.showerror("Error", "Recipient and message are required")
            return
        
        try:
            iv, ciphertext = self.client.send_message(recipient, message)
            self.iv_entry.delete(0, tk.END)
            self.iv_entry.insert(0, iv.hex())
            
            self.ciphertext_entry.delete("1.0", tk.END)
            self.ciphertext_entry.insert("1.0", ciphertext.hex())
            
            messagebox.showinfo("Success", "Message encrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt message: {str(e)}")
    
    def copy_encrypted(self):
        """Copy encrypted message to clipboard."""
        iv = self.iv_entry.get()
        ciphertext = self.ciphertext_entry.get("1.0", tk.END).strip()
        
        if not iv or not ciphertext:
            messagebox.showerror("Error", "No encrypted message to copy")
            return
        
        self.root.clipboard_clear()
        self.root.clipboard_append(f"{iv}\n{ciphertext}")
        messagebox.showinfo("Success", "Encrypted message copied to clipboard")
    
    def receive_message(self):
        """Handle receiving a message."""
        if not self.client:
            messagebox.showerror("Error", "Not connected to server")
            return
        
        sender = self.sender_entry.get()
        iv_hex = self.receive_iv_entry.get()
        ciphertext_hex = self.receive_ciphertext_entry.get("1.0", tk.END).strip()
        
        if not sender or not iv_hex or not ciphertext_hex:
            messagebox.showerror("Error", "Sender, IV and ciphertext are required")
            return
        
        try:
            iv = bytes.fromhex(iv_hex)
            ciphertext = bytes.fromhex(ciphertext_hex)
            decrypted = self.client.receive_message(sender, iv, ciphertext)
            
            self.decrypted_text.config(state="normal")
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert("1.0", decrypted)
            self.decrypted_text.config(state="disabled")
            
            # Update messages list
            self.update_messages_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt message: {str(e)}")
    
    def update_messages_list(self):
        """Update the messages listbox."""
        if not self.client:
            return
        
        self.messages_listbox.delete(0, tk.END)
        for i, (sender, message) in enumerate(self.client.messages):
            display_msg = f"{i+1}. From {sender}: {message[:50]}{'...' if len(message) > 50 else ''}"
            self.messages_listbox.insert(tk.END, display_msg)
    
    def view_message(self):
        """View the selected message."""
        selection = self.messages_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        if index < len(self.client.messages):
            sender, message = self.client.messages[index]
            
            self.message_view.config(state="normal")
            self.message_view.delete("1.0", tk.END)
            self.message_view.insert("1.0", f"From: {sender}\n\n{message}")
            self.message_view.config(state="disabled")
    
    def refresh_stats(self):
        """Refresh the statistics display."""
        if not self.client:
            return
        
        self.client.print_performance_stats()
        
        stats_text = f"Performance Statistics for {self.client.identity}:\n\n"
        
        if self.client.encryption_times:
            stats_text += "Encryption Times:\n"
            for size, times in sorted(self.client.encryption_times.items()):
                avg_time = sum(times) / len(times)
                stats_text += f"  Message size {size} bytes: {avg_time:.6f} seconds (avg of {len(times)} operations)\n"
        
        if self.client.decryption_times:
            stats_text += "\nDecryption Times:\n"
            for size, times in sorted(self.client.decryption_times.items()):
                avg_time = sum(times) / len(times)
                stats_text += f"  Message size {size} bytes: {avg_time:.6f} seconds (avg of {len(times)} operations)\n"
        
        self.stats_text.config(state="normal")
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", stats_text)
        self.stats_text.config(state="disabled")


def main():
    """Main function to run the GUI."""
    root = tk.Tk()
    root.geometry("800x600")
    app = IBEClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()