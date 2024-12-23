import socket
import argparse

def get_dns_server():
    """Detecta automaticamente o servidor DNS configurado no sistema."""
    with open('/etc/resolv.conf', 'r') as file:
        for line in file:
            if line.startswith('nameserver'):
                return line.split()[1]
    raise RuntimeError("Não foi possível detectar o servidor DNS local.")

def build_query(domain, record_type):
    """Constrói a consulta DNS em formato binário."""
    import random

    transaction_id = random.randint(0, 65535).to_bytes(2, 'big')
    flags = b'\x01\x00'  
    questions = b'\x00\x01'  
    answer_rrs = b'\x00\x00' 
    authority_rrs = b'\x00\x00' 
    additional_rrs = b'\x00\x00'  

    qname = b''.join(bytes([len(part)]) + part.encode() for part in domain.split('.')) + b'\x00'

    record_types = {
        "A": b'\x00\x01',
        "AAAA": b'\x00\x1c',
        "MX": b'\x00\x0f',
    }
    qtype = record_types.get(record_type.upper(), b'\x00\x01')
    qclass = b'\x00\x01'  

    return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + qname + qtype + qclass

def parse_response(response):
    """Analisa a resposta do servidor DNS e retorna os resultados."""
    header = response[:12]
    transaction_id, flags, questions, answer_rrs, authority_rrs, additional_rrs = header[:2], header[2:4], header[4:6], header[6:8], header[8:10], header[10:12]
    answers = response[12:]

    results = []
    while answers:
        pointer_or_length = answers[0]
        if pointer_or_length & 0xc0 == 0xc0:  
            answers = answers[2:] 
        else:
            length = pointer_or_length
            answers = answers[length + 1:]

        if len(answers) >= 10:  
            record_type = int.from_bytes(answers[0:2], 'big')
            data_length = int.from_bytes(answers[8:10], 'big')
            if record_type == 1: 
                ip = '.'.join(map(str, answers[10:10 + data_length]))
                results.append(ip)
            answers = answers[10 + data_length:]
    return results

def main():
    parser = argparse.ArgumentParser(description="Cliente DNS simples para consultas de nomes de domínio.")
    parser.add_argument("domain", help="Nome do domínio a ser consultado.")
    parser.add_argument("record_type", nargs='?', default="A", help="Tipo de registro DNS (A, AAAA, MX). Default: A")
    parser.add_argument("dns_server", nargs='?', default=None, help="Servidor DNS. Default: servidor DNS local.")
    args = parser.parse_args()

    dns_server = args.dns_server if args.dns_server else get_dns_server()
    query = build_query(args.domain, args.record_type)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5.0)
        sock.sendto(query, (dns_server, 53))
        response, _ = sock.recvfrom(512)

    results = parse_response(response)
    print(f"Domínio consultado: {args.domain}")
    print(f"Tipo de registro: {args.record_type}")
    if results:
        print(f"Resultados:\n" + '\n'.join(results))
    else:
        print("Nenhum resultado encontrado.")

if __name__ == "__main__":
    main()
