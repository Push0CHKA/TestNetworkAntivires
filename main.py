import logging

from scapy.layers.inet import TCP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import argparse
from pathlib import Path
from scapy.all import *

format_str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"


def get_http_headers(http_payload):
    try:
        headers_raw = http_payload[:http_payload.index(b"\r\n\r\n") + 2]
        headers = dict(re.findall(b"(?P<name>.*?): (?P<value>.*?)\\r\\n", headers_raw))

    except ValueError as err:
        logging.error('Could not find \\r\\n\\r\\n - %s' % err)
        return None
    except Exception as err:
        logging.error('Exception found trying to parse raw headers - %s' % err)
        logging.debug(str(http_payload))
        return None

    if b"Content-Type" not in headers:
        logging.debug('Content Type not present in headers')
        logging.debug(headers.keys())
        return None
    return headers


def extract_object(headers, http_payload):
    object_extracted = None
    object_type = None

    content_type_filters = [b'application/x-msdownload', b'application/octet-stream']

    try:
        if b'Content-Type' in headers.keys():
            if headers[b'Content-Type'] in content_type_filters:
                object_extracted = http_payload[http_payload.index(b"\r\n\r\n") + 4:]
                object_type = object_extracted[:2]
                logging.info("Object Type: %s" % object_type)
            else:
                logging.debug('Content Type did not matched with filters - %s' % headers[b'Content-Type'])
                if len(http_payload) > 10:
                    logging.debug('Object first 50 bytes - %s' % str(http_payload[:50]))
        else:
            logging.info('No Content Type in Package')
            logging.debug(headers.keys())

        if b'Content-Length' in headers.keys():
            logging.info("%s: %s" % (b'Content-Lenght', headers[b'Content-Length']))
    except Exception as err:
        logging.error('Exception found trying to parse headers - %s' % err)
        return None, None
    return object_extracted, object_type


def create_output_directory_folder(directory_name, output_directory='objects') -> str:
    if not os.path.exists(output_directory):
        logging.debug('Directory %s does not exists - creating' % output_directory)
        os.mkdir(output_directory)
    directory_name = directory_name.replace('.pcap', '')
    target_path = os.path.join(os.getcwd(), output_directory, directory_name)
    if not os.path.exists(target_path):
        logging.debug('Path %s does not exists - creating.' % target_path)
        os.mkdir(target_path)
    return target_path


def parse_pcap_filename(pcap_file) -> str:
    parts = pcap_file.split('/')
    logging.debug('Pcap File path %s - Parts %d' % (pcap_file, len(parts)))
    if len(parts) > 1:
        return parts[-1]
    else:
        return parts[0]


def extract_http_objects(pcap_file, output_directory):
    logging.info('Starting to parse pcap/s')

    filtered_object_types = [b'MZ']
    pcap_file_name = parse_pcap_filename(pcap_file)
    pcap_flow = rdpcap(pcap_file)
    target_directory = create_output_directory_folder(pcap_file_name, output_directory)

    sessions = pcap_flow.sessions()

    objects_count = 0
    objects_saved = 0

    for session in sessions:
        http_payload = bytes()
        for packet in sessions[session]:
            if packet.haslayer(TCP):
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    if packet[TCP].payload:
                        payload = packet[TCP].payload
                        http_payload += raw(payload)
                if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    logging.debug('https traffic detected')

        if len(http_payload):
            headers = get_http_headers(http_payload)

            if headers is None:
                continue

            logging.debug("HTTP Payload lenght: %d" % len(http_payload))
            object_found, object_type = extract_object(headers, http_payload)

            if object_found is not None and object_type is not None:
                objects_count += 1
                if len(object_found) == 0:
                    logging.debug("Object found with lenght 0")
                    continue
                if object_type not in filtered_object_types:
                    logging.debug("Non parseable Content Type %s" % (object_type))
                    continue

                object_name = "%s_object_found_%d" % (pcap_file_name, objects_count)

                fd = open("%s/%s" % (target_directory, object_name), "wb")
                fd.write(object_found)
                fd.close()
                objects_saved += 1
            elif object_found:
                logging.debug('Object found lenght: %d' % len(object_found))
            elif object_type:
                logging.debug('Object Type: %d' % object_type)

    logging.info('Parsed all files')
    logging.info("Total Number of Objects Found: %d" % (objects_count))
    logging.info("Total Number of Objects Saved: %d" % (objects_saved))


def extract_http_objects_from_directory(target_directory, output_directory):
    # List all files in the directory
    directory_files = os.listdir(target_directory)
    logging.debug('Target directory has %d files for extraction' % len(directory_files))
    for target_file in directory_files:
        print(target_file)
        # If file is a pcap we parse
        if Path(target_file).suffix == '.pcap':
            logging.debug('new pcap file to parse %s' % target_file)
            extract_http_objects(os.path.join(target_directory, target_file), output_directory)
        else:
            logging.debug('not a pcap file %s' % Path(target_file).suffix)
    logging.info('All files parsed')


def print_help():
    print("python pcap_file_extraction.py --inputpcap <file>")


def main():
    parser = argparse.ArgumentParser(description="Parse pcap and extract files")
    parser.add_argument('-i', '--inputpcap', required=True, help='PCAP file or Directory to process files')
    parser.add_argument('-o', '--outputdir', default='objects', type=str,
                        help='Output Directory where to place the Extracted files')
    parser.add_argument('-d', '--debug', help='Enable Debugging Logging', action='store_const', dest='loglevel',
                        const=logging.DEBUG, default=logging.INFO)
    parser.add_argument('-l', '--log', help='Specificy Log File', dest='logfile', type=str, default='extractor.log')

    args = parser.parse_args()

    logging.basicConfig(filename=args.logfile, format=format_str, level=args.loglevel)

    logging.info("Starting up")
    if args.inputpcap:
        if os.path.isfile(args.inputpcap):
            print('Parsing file - %s' % args.inputpcap)
            extract_http_objects(args.inputpcap, args.outputdir)
        elif os.path.isdir(args.inputpcap):
            print('Parsing Directory - %s' % args.inputpcap)
            extract_http_objects_from_directory(args.inputpcap, args.outputdir)

    logging.info('Finishing up')


if __name__ == "__main__":
    main()
