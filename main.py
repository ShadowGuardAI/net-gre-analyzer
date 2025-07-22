import socket
import argparse
import logging
import struct
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# GRE Header Format (RFC 2784) - Basic version
GRE_HEADER_FORMAT = '!H H I'  # C, Protocol Type, Checksum/Offset, Key, Sequence Number


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Analyzes GRE (Generic Routing Encapsulation) packets.")
    parser.add_argument("pcap_file", help="Path to the PCAP file containing GRE packets.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (debug level).")
    parser.add_argument("-o", "--output", help="Output file to save extracted data (optional).")
    parser.add_argument("-l", "--limit", type=int, help="Limit the number of packets to analyze.")
    return parser.parse_args()


def analyze_gre_packet(packet_data, output_file=None):
    """
    Analyzes a single GRE packet, extracts information, and logs the results.
    Args:
        packet_data (bytes): The raw bytes of the GRE packet.
        output_file (str, optional): Path to the output file for writing. Defaults to None.
    Returns:
        None
    """
    try:
        # Unpack the GRE header
        gre_header_size = struct.calcsize(GRE_HEADER_FORMAT)
        if len(packet_data) < gre_header_size:
            logging.warning("Packet too short to contain a complete GRE header.")
            return

        gre_header = struct.unpack(GRE_HEADER_FORMAT, packet_data[:gre_header_size])
        flags, protocol_type, checksum_key_seq = gre_header

        # Extract GRE Flags
        c_bit = (flags >> 15) & 1  # Checksum Present
        r_bit = (flags >> 14) & 1  # Routing Present
        k_bit = (flags >> 13) & 1  # Key Present
        s_bit = (flags >> 12) & 1  # Sequence Number Present
        seq_bit = (flags >> 11) & 1  # Strict Source Route Present
        recur_bit = flags & 0x07  # Recursion Control

        # Determine the size of the header based on the flags
        header_size = gre_header_size

        # Key Present
        key = None
        if k_bit:
            header_size += 4

        # Sequence Number Present
        seq_number = None
        if s_bit:
            header_size += 4

        # Checksum present
        checksum = None
        if c_bit:
            header_size += 4

        # Routing present (Not implemented)
        if r_bit:
            logging.warning("Routing field present, analysis not implemented.")
            return
        
        if len(packet_data) < header_size:
            logging.warning("Packet too short based on GRE flags.")
            return

        encapsulated_data = packet_data[header_size:]

        # Determine the encapsulated protocol based on the protocol type
        protocol = None
        try:
            protocol = socket.ntohs(protocol_type)  # Convert to host byte order
        except OverflowError:
            logging.warning(f"Unknown protocol type: {protocol_type}")
            return

        protocol_name = socket.getservbyport(protocol, 'tcp') if protocol in range(0, 65536) else "Unknown"
        
        # Log the information
        log_message = (
            f"GRE Flags: C={c_bit}, R={r_bit}, K={k_bit}, S={s_bit}, Recursion={recur_bit}\n"
            f"Encapsulated Protocol: {protocol_name} (EtherType: {hex(protocol_type)})\n"
            f"Payload Length: {len(encapsulated_data)} bytes"
        )
        logging.info(log_message)

        # Optional output to file
        if output_file:
            try:
                with open(output_file, "a") as f:
                    f.write(log_message + "\n")
            except Exception as e:
                logging.error(f"Error writing to output file: {e}")

    except struct.error as e:
        logging.error(f"Error unpacking GRE header: {e}")
    except OSError as e:
        logging.error(f"Error: {e}.  This often occurs if the protocol number is not found.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")


def read_pcap(pcap_file, limit=None, output_file=None):
    """
    Reads a PCAP file and analyzes each packet for GRE encapsulation.
    Args:
        pcap_file (str): Path to the PCAP file.
        limit (int, optional): Maximum number of packets to analyze. Defaults to None (all packets).
        output_file (str, optional): Path to the output file. Defaults to None.
    Returns:
        None
    """
    try:
        with open(pcap_file, "rb") as f:
            # Read the PCAP Global Header (24 bytes) - Check for magic number (first 4 bytes)
            magic_number = f.read(4)
            if magic_number not in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'):
                raise ValueError("Invalid PCAP file format.")

            # Skip the rest of the global header (20 bytes)
            f.seek(20, 1)  # Seek relative to current position

            packet_count = 0
            while True:
                # Read Packet Header (16 bytes)
                packet_header = f.read(16)
                if not packet_header:
                    break  # End of file

                # Unpack packet header - Assuming standard PCAP format
                timestamp_seconds, timestamp_microseconds, captured_length, original_length = struct.unpack("<IIII", packet_header)

                # Read Packet Data
                packet_data = f.read(captured_length)

                # Basic check if the packet appears to be an IPv4 packet encapsulated inside Ethernet.
                # Check for Ethernet header (14 bytes) followed by IPv4 EtherType (0x0800)
                if len(packet_data) > 14 and packet_data[12:14] == b'\x08\x00':
                    # Check for IPv4 header (at least 20 bytes after the Ethernet header)
                    ip_header_start = 14  # After Ethernet header
                    if len(packet_data) >= ip_header_start + 20:
                        ip_version = packet_data[ip_header_start] >> 4 # Get version from first byte
                        if ip_version == 4:
                            # Check for GRE protocol inside IPv4 (protocol number 47)
                            ip_protocol = packet_data[ip_header_start + 9]  # Protocol field is at offset 9

                            if ip_protocol == 47:  # 47 is GRE Protocol Number
                                ip_header_length = (packet_data[ip_header_start] & 0x0F) * 4  # IHL field in words of 4 bytes
                                gre_packet_start = ip_header_start + ip_header_length
                                if len(packet_data) > gre_packet_start:
                                    gre_data = packet_data[gre_packet_start:]
                                    analyze_gre_packet(gre_data, output_file)
                                else:
                                    logging.warning("Incomplete IPv4 packet containing GRE.")
                            else:
                                logging.debug("IPv4 packet, but not GRE encapsulated.")
                        else:
                            logging.debug("Not an IPv4 packet.")
                    else:
                        logging.warning("Incomplete Ethernet/IPv4 packet.")
                else:
                    logging.debug("Not an Ethernet/IPv4 packet.")

                packet_count += 1
                if limit and packet_count >= limit:
                    logging.info(f"Analysis limit reached ({limit} packets).")
                    break

    except FileNotFoundError:
        logging.error(f"PCAP file not found: {pcap_file}")
        sys.exit(1)
    except ValueError as e:
        logging.error(f"Invalid PCAP format: {e}")
        sys.exit(1)
    except struct.error as e:
        logging.error(f"Error unpacking packet header: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


def main():
    """
    Main function to parse arguments and start the analysis.
    """
    args = setup_argparse()

    # Configure logging level based on verbosity
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    logging.info(f"Starting GRE packet analysis on {args.pcap_file}...")
    read_pcap(args.pcap_file, args.limit, args.output)
    logging.info("GRE packet analysis completed.")


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Analyze all packets in a PCAP file:
#    python net_gre_analyzer.py my_capture.pcap

# 2. Analyze only the first 100 packets:
#    python net_gre_analyzer.py my_capture.pcap --limit 100

# 3. Analyze packets and save the output to a file:
#    python net_gre_analyzer.py my_capture.pcap --output gre_analysis.txt

# 4. Enable verbose logging:
#    python net_gre_analyzer.py my_capture.pcap --verbose

# 5. Combine limit and output file:
#    python net_gre_analyzer.py my_capture.pcap --limit 50 --output limited_analysis.txt