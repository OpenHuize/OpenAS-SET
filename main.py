import socket
import re

IRR_SERVER = "whois.radb.net"
IRR_PORT = 43
MAX_DEPTH = 10

def query_irr(query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((IRR_SERVER, IRR_PORT))
    sock.sendall(query.encode())

    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk

    return data.decode()

def get_as_set_members(as_set_name, depth, processed_as_sets, final_result):
    if as_set_name in processed_as_sets:
        return
    processed_as_sets.add(as_set_name)
    query = f"-k {as_set_name}\n"
    response = query_irr(query)
    lines = response.split("\n")

    members = []
    for line in lines:
        if line.startswith("members"):
            members.append(line.split(":")[1].strip())
    if depth < MAX_DEPTH:
        for member in members:
            if member.startswith("AS-"):
                get_as_set_members(member, depth+1, processed_as_sets, final_result)
            elif re.match("^AS[0-9]+$", member): # # Match ASN, keep only AS numbers
                final_result.add(member)

def print_final_result(final_result):
    print("descr:           https://github.com/OpenHuize/OpenAS-SET")
    for asn in final_result:
        print("members:         " + asn)


if __name__ == "__main__":
    final_result = set()
    processed_as_sets = set()
    get_as_set_members("AS-HUIZE", 0, processed_as_sets, final_result)
    print_final_result(final_result)

