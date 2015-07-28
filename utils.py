# Thanks baboon project for the code.
import subprocess


def cmp_to_key(mycmp):
    """ Converts a cmp= function into a key= function.
    """

    class K(object):
        def __init__(self, obj, *args):
            self.obj = obj

        def __lt__(self, other):
            return mycmp(self.obj, other.obj) < 0

        def __gt__(self, other):
            return mycmp(self.obj, other.obj) > 0

        def __eq__(self, other):
            return mycmp(self.obj, other.obj) == 0

        def __le__(self, other):
            return mycmp(self.obj, other.obj) <= 0

        def __ge__(self, other):
            return mycmp(self.obj, other.obj) >= 0

        def __ne__(self, other):
            return mycmp(self.obj, other.obj) != 0

        def __hash__(self):
            raise TypeError('hash not implemented')

    return K


def exec_cmd(cmd, cwd=None):
    """ Execute the cmd command in a subprocess.
    """

    # Create the process and run it.
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, shell=True, cwd=cwd)
    output, errors = proc.communicate()

    return (proc.returncode, output, errors)
