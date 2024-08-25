require 'socket'
require 'ipaddr'
require 'json'
require 'csv'
require 'thread'
require 'timeout'  # For timeout handling

# Color codes for output formatting (optional)
COLOR_GREEN = "\e[32m"
COLOR_RED = "\e[31m"
COLOR_YELLOW = "\e[33m"
COLOR_CYAN = "\e[36m"
COLOR_ORANGE = "\e[33m"
RESET_COLOR = "\e[0m"

VERSION = "2.0"

# Resolves hostname from IP address
def resolve_hostname(ip)
  begin
    Socket.gethostbyaddr(ip)[0]
  rescue SocketError
    nil
  end
end

# Creates a socket connection
def create_socket(ip, port, timeout)
  begin
    family = Socket::AF_INET6 if ip.include?(':') else Socket::AF_INET
    sock = Socket.new(family, Socket::SOCK_STREAM)
    sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)  # Disable Nagle's algorithm for faster communication
    sock.connect(SocketAddr.new(family, port, ip))
    sock
  rescue StandardError => e
    nil
  end
end

# Retrieves SSH banner
def get_ssh_banner(sock, use_help_request: false)
  begin
    banner = sock.recv(1024).encode('ascii', errors: 'ignore').strip
    return banner unless banner.empty? || !use_help_request
    help_str = "HELP\n"
    sock.send(help_str)
    banner = sock.recv(1024).encode('ascii', errors: 'ignore').strip
    return banner
  rescue StandardError => e
    "Error retrieving banner: #{e.message}"
  ensure
    sock.close if sock
  end

# Vulnerability scanning function
def check_vulnerability(ip, port, timeout, gracetimecheck, result_queue, resolve_hostnames)
  hostname = resolve_hostname(ip) if resolve_hostnames
  sock = create_socket(ip, port, timeout)
  if !sock
    result_queue.push([ip, port, hostname, 'closed', "Port closed"])
    return
  end

  banner = get_ssh_banner(sock)
  sock.close

  if !banner
    result_queue.push([ip, port, hostname, 'failed', "Failed to retrieve SSH banner"])
    return
  end

  return unless banner.include?('SSH-2.0-OpenSSH')

  vulnerable_versions = [
      'OpenSSH_1.2.2p1', 'OpenSSH_1.2.3p1', 'OpenSSH_2.1.1p2', 'OpenSSH_2.1.1p3',
      'OpenSSH_2.0.0p1', 'OpenSSH_2.3.0p1', 'OpenSSH_2.5.1p1', 'OpenSSH_2.5.1p2',
      'OpenSSH_2.5.2p2', 'OpenSSH_2.9', 'OpenSSH_2.9p1', 'OpenSSH_2.9.9',
      'OpenSSH_2.9.9p1', 'OpenSSH_2.9p2', 'OpenSSH_3.0', 'OpenSSH_3.0p1',
      'OpenSSH_3.0.1', 'OpenSSH_3.0.1p1', 'OpenSSH_3.0.2p1', 'OpenSSH_3.1',
      'OpenSSH_3.1p1', 'OpenSSH_3.2.2', 'OpenSSH_3.2.2p1', 'OpenSSH_3.2.3',
      'OpenSSH_3.2.3p1', 'OpenSSH_3.3', 'OpenSSH_3.3p1', 'OpenSSH_3.4',
      'OpenSSH_3.4p1', 'OpenSSH_3.5', 'OpenSSH_3.5p1', 'OpenSSH_3.6',
      'OpenSSH_3.6p1', 'OpenSSH_3.6.1', 'OpenSSH_3
اینو با پسوند rb ذخیره کن😀🤝✔️
