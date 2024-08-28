

class Node:
    def __init__(self, new_data):
        self.data = new_data
        self.next = None


class Queue:
    ''' queue implementation using linked list '''

    def __init__(self):
        self.head = None
        self.tail = None
        self.size = 0

    def is_empty(self):
        return self.head is None and self.tail is None
    
    def len(self):
        return self.size

    def add(self, data):
        node = Node(data)

        if self.tail is None:
            self.head = self.tail = node
            return

        self.tail.next = node
        self.tail = node
        self.size += 1

    def pop(self):
        assert not self.is_empty()
        data = self.head.data
        self.head = self.head.next

        if self.head is None:
            self.tail = None

        self.size -= 1
        return data

    def first(self):
        assert not self.is_empty()
        return self.head.data

    def last(self):
        assert not self.is_empty()
        return self.tail.data
