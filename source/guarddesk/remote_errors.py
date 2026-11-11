"""Remote protocol errors without center persistence or credentials."""

class RemoteError(Exception):
    def __init__(self,status,message):self.status,self.message=status,message

