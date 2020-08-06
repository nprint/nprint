import os
import argparse
import subprocess

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap')
    parser.add_argument('test_name')
    parser.add_argument('-k', '--keep_files', action='store_true')
    args = parser.parse_args()
    
    run_test(args.pcap, args.test_name, args.keep_files)

def run_test(pcap, test_type, keep_files):
    pcap_text = '{0}_test.txt'.format(test_type)
    nprint = '{0}.npt'.format(test_type)
    reverse_pcap = '{0}_rebuilt.pcap'.format(test_type)
    nprint_text = '{0}_test_rebuilt.txt'.format(test_type)

    files = [pcap_text, nprint, reverse_pcap, nprint_text]

    print('Test name {0}'.format(test_type))
    # TCPDUMP 
    print('  1. Running tcpdump on pcap')
    subprocess.run('sudo tcpdump -r {0} -nnvvtK > {1}'.format(pcap, pcap_text), shell=True)
    # convert pcap to nPrint
    print('  2. Creating nPrint for pcap')
    subprocess.run('nprint -r {0} -4 -t -i -u -6 -p 2000 -w {1}'.format(pcap, nprint), shell=True)
    # convert nPrint to back to pcap
    print('  3. reversing nPrint back to pcap')
    subprocess.run('nprint -r {0} -w {1} -z'.format(nprint, reverse_pcap), shell=True)
    # TCPDUMP
    print('  4. Running tcpdump on reversed pcap')
    subprocess.run('sudo tcpdump -r {0} -nnvvtK > {1}'.format(reverse_pcap, nprint_text), shell=True)
    # Diff
    print('  5. Comparing results')
    proc = subprocess.run('diff {0} {1}'.format(pcap_text, nprint_text), shell=True)
    if proc.returncode == 0:
        print('    RESULT: PASS! Rebuilt pcap matched original!')
        if not keep_files:
            print('      Removing files from test, (force file retention with -k option)')
            for f in files:
                os.remove(f)
    else:
        print('    RESULT: FAIL! Rebuilt pcap MISMATCH with original, keeping files')

if __name__ == '__main__':
    main()
