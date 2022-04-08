queue = []

queue.append('a')
queue.append('b')
queue.append('c')

print("Initial queue")
print(queue)

queue.pop(0)
print(queue)
print(len(queue))

queue.append('d')
print(queue)

queue.pop(0)
print(queue)