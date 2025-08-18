module.exports = function(io) {
  const activeRooms = new Map();  // roomId => Set(socketIds)
  const roomCodes = new Map();    // roomId => current code

  io.on('connection', (socket) => {
    console.log('🧠 Socket connected:', socket.id);

    socket.on('createRoom', (roomId) => {
      if (!activeRooms.has(roomId)) {
        activeRooms.set(roomId, new Set());
        roomCodes.set(roomId, '');
      }
      socket.join(roomId);
      activeRooms.get(roomId).add(socket.id);
      socket.emit('roomCreated', roomId);
    });

    socket.on('joinRoom', (roomId) => {
      if (!activeRooms.has(roomId)) {
        socket.emit('joinError', '❌ Room does not exist');
        return;
      }
      socket.join(roomId);
      activeRooms.get(roomId).add(socket.id);
      const currentCode = roomCodes.get(roomId) || '';
      socket.emit('roomJoined', { roomId, currentCode });
    });

    socket.on('codeChange', ({ room, code }) => {
      roomCodes.set(room, code);
      socket.to(room).emit('codeUpdate', code);
    });

    socket.on('leaveRoom', (roomId) => {
      socket.leave(roomId);
      if (activeRooms.has(roomId)) {
        activeRooms.get(roomId).delete(socket.id);
        if (activeRooms.get(roomId).size === 0) {
          activeRooms.delete(roomId);
          roomCodes.delete(roomId);
        }
      }
    });

    socket.on('chatMessage', ({ room, message, timestamp, id, sender }) => {
      socket.to(room).emit('newChatMessage', {
        message,
        timestamp,
        id,
        sender
      });
    });

    socket.on('disconnect', () => {
      for (const [roomId, members] of activeRooms.entries()) {
        if (members.has(socket.id)) {
          members.delete(socket.id);
          if (members.size === 0) {
            activeRooms.delete(roomId);
            roomCodes.delete(roomId);
          }
        }
      }
    });
  });
};