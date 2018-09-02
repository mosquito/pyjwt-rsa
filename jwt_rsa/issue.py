import argparse

from .token import JWT
from .rsa import load_private_key


parser = argparse.ArgumentParser()
parser.add_argument()


def main():
    arguments = parser.parse_args()
    jwt = JWT(private_key=load_private_key(arguments.private_key))
