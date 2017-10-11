import flash.errors.EOFError;
import flash.events.Event;
import flash.events.IOErrorEvent;
import flash.events.ProgressEvent;
import flash.events.SecurityErrorEvent;
import flash.external.ExternalInterface;
import flash.Lib;
import flash.net.Socket;
import flash.system.Security;
import flash.utils.ByteArray;
import haxe.crypto.Base64;
import haxe.io.Bytes;

/**
  Result is returned by ExternalInterface calls and unambiguously exposes the
  value or error.
 **/
typedef Result<T> = {
	@:optional var value : T;
	@:optional var error : String;
}

/**
  Event that is received by subscribed listeners.
 **/
typedef SocketEvent = {
	var socket : Int;

	/**
	  One of: connect, close, ioError, securityError, socketData.
	 **/
	var type : String;

	/**
	  Error message (for ioError or securityError).
	 **/
	@:optional var error : String;

	/**
	  Bytes that are currently available for retrieval (for socketData).
	 **/
	@:optional var bytesAvailable: UInt;
}

class TaggedSocket extends Socket {
	public var id : Int;

	/**
	  Buffer to store received data. This allows the client to read data
	  after the peer closed the connection.
	 **/
	public var receiveBuffer : ByteArray;

	/**
	  Whether the connect call has finished with a result.
	 **/
	public var connectResultReady: Bool;

	/**
	  Last error from connection or read attempt.
	 **/
	public var lastError : String;

	public function new() {
		super();
		receiveBuffer = new ByteArray();
	}
}

class SocketAPI {
	var nextSocketId : Int;
	var sockets : Map<Int, TaggedSocket>;
	var listeners : Array<String>;

	public function new() {
		if (!ExternalInterface.available) {
			throw "ExternalInterface is required!";
		}

		nextSocketId = 1;
		sockets = new Map();
		listeners = [];

		// Helpers
		ExternalInterface.addCallback("subscribe", subscribe);
		ExternalInterface.addCallback("unsubscribe", unsubscribe);
		ExternalInterface.addCallback("loadPolicyFile", loadPolicyFile);

		// Socket API
		ExternalInterface.addCallback("create", create);
		ExternalInterface.addCallback("connect", connect);
		ExternalInterface.addCallback("isConnected", isConnected);
		ExternalInterface.addCallback("send", send);
		ExternalInterface.addCallback("receive", receive);
		ExternalInterface.addCallback("close", close);
	}

	static function main() {
		ExternalInterface.marshallExceptions = true; // TODO remove debug
		new SocketAPI();
	}

	function log(p1:Dynamic, p2:Dynamic) {
		ExternalInterface.call("console.log", p1, p2);
	}

	function getSocket<T>(socketId:Int):TaggedSocket {
		var sock = sockets[socketId];
		if (sock == null) {
			throw "No such socket";
		}
		return sock;
	}

	/**
	  Fills the receive buffer up to maxLength (or unbounded if 0).
	  This internal buffer exists to avoid losing data if the remote peer
	  closes the connection.
	 **/
	function fillSocketBuffer(sock:TaggedSocket, maxLength:UInt = 0) {
		var maxRead:UInt = 0;
		if (maxLength > 0) {
			if (maxLength <= sock.receiveBuffer.length) {
				// Got sufficient data.
				return;
			}
			maxRead = maxLength - sock.receiveBuffer.length;
			if (maxRead > sock.bytesAvailable) {
				maxRead = sock.bytesAvailable;
			}
		}
		try {
			sock.readBytes(sock.receiveBuffer,
					sock.receiveBuffer.length, maxRead);
		} catch (err:Dynamic) {
			sock.lastError = err.toString();
		}
	}

	function handleEvent(evt:Event):Void {
		log("handleEvent", evt); // TODO remove debug
		var sock:TaggedSocket = evt.target;
		var socketEvent:SocketEvent = {
			type: evt.type,
			socket: sock.id
		};
		switch (evt.type) {
		case Event.CONNECT:
			sock.connectResultReady = true;

		case IOErrorEvent.IO_ERROR | SecurityErrorEvent.SECURITY_ERROR:
			socketEvent.error = evt.toString();
			sock.connectResultReady = true;
			sock.lastError = evt.toString();

		case ProgressEvent.SOCKET_DATA:
			// TODO limit maximum buffer size to avoid memory exhaustion?
			fillSocketBuffer(sock);
			socketEvent.bytesAvailable = sock.receiveBuffer.length;

		case Event.CLOSE:
		}
		for (listener in listeners) {
			try {
				ExternalInterface.call(listener, socketEvent);
			} catch (err:Dynamic) {
				log("Callback "  + listener + " failed", err);
			}
		}
	}

	function addListeners(sock:TaggedSocket):Void {
		sock.addEventListener(Event.CONNECT, handleEvent);
		// Error #2031 can occur when:
		// - No service is listening on port (TCP RST).
		sock.addEventListener(IOErrorEvent.IO_ERROR, handleEvent);
		// Error #2048 can occur when:
		// - No policy service was running.
		// - Policy service runs on unprivileged port (>1024) while the
		//   destination port is a privileged port.
		sock.addEventListener(SecurityErrorEvent.SECURITY_ERROR,
				handleEvent);
		sock.addEventListener(ProgressEvent.SOCKET_DATA, handleEvent);
		sock.addEventListener(Event.CLOSE, handleEvent);
	}

	function removeListeners(sock:TaggedSocket):Void {
		sock.removeEventListener(Event.CONNECT, handleEvent);
		sock.removeEventListener(IOErrorEvent.IO_ERROR, handleEvent);
		sock.removeEventListener(SecurityErrorEvent.SECURITY_ERROR,
				handleEvent);
		sock.removeEventListener(ProgressEvent.SOCKET_DATA,
				handleEvent);
		sock.removeEventListener(Event.CLOSE, handleEvent);
	}

	/**
	  Registers a callback that will be invoked for socket events.
	 **/
	public function subscribe(callback:String):Void {
		if (listeners.indexOf(callback) != -1) {
			listeners.push(callback);
		}
	}

	/**
	  Unregister any registered socket event listeners.
	 **/
	public function unsubscribe(callback:String):Void {
		listeners.remove(callback);
	}

	/**
	  Override the master policy file server at port 843.

	  http://help.adobe.com/en_US/as3/dev/WS5b3ccc516d4fbf351e63e3d118a9b90204-7c63.html
	 **/
	public function loadPolicyFile(url:String):Result<Void> {
		try {
			Security.loadPolicyFile(url);
			return {};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Creates a new socket.

	  Returns the socket identifier (Int).
	 **/
	public function create():Result<Int> {
		try {
			var sock = new TaggedSocket();
			sock.id = nextSocketId++;
			addListeners(sock);
			sockets[sock.id] = sock;
			return {value: sock.id};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Open a socket connection to the given host and port.

	  To learn about the success outcome, register an event listener using
	  the subscribe method first.
	 **/
	public function connect(socket:Int, host:String, port:Int):Result<Void> {
		try {
			var sock = getSocket(socket);
			sock.connect(host, port);
			return {};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Checks whether a socket is connected.

	  Returns a boolean connection status (if the socket connection attempt
	  succeeded), nothing (if the connection is still pending) or an error
	  (if the socket does not exist or if the connection attempt failed).
	 **/
	public function isConnected(socket:Int):Result<Bool> {
		try {
			var sock = getSocket(socket);
			if (!sock.connectResultReady) {
				return {};
			}
			if (sock.lastError != null) {
				throw sock.lastError;
			}
			return {value: sock.connected};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Base64-decode the data and send it to the socket.
	 **/
	public function send(socket:Int, buffer:String):Result<Void> {
		try {
			var sock = getSocket(socket);
			var data = Base64.decode(buffer).getData();
			sock.writeBytes(data);
			sock.flush();
			return {};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Reads data from the socket.

	  Returns base64-encoded data (String) on success. At most "length"
	  bytes are encoded. If no data is currently available, an empty string
	  is returned.
	 **/
	public function receive(socket:Int, length:UInt):Result<String> {
		try {
			var sock = getSocket(socket);
			var avail = sock.receiveBuffer.length;
			if (length > avail) {
				length = avail;
			}
			if (avail == 0 && !sock.connected) {
				throw new EOFError("socket is closed");
			}
			if (length == 0) {
				return {value: ""};
			}
			if (sock.lastError != null) {
				throw sock.lastError;
			}
			var newBuffer:ByteArray = new ByteArray();
			var result:ByteArray = sock.receiveBuffer;
			if (length < avail) {
				// partial read, extract remaining part.
				result.position = length;
				result.readBytes(newBuffer);
				// truncate read part.
				result.length = length;
			}
			sock.receiveBuffer = newBuffer;
			result.position = 0;
			return {value: Base64.encode(Bytes.ofData(result))};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}

	/**
	  Closes a socket.
	 **/
	public function close(socket:Int):Result<Void> {
		try {
			var sock = getSocket(socket);
			sock.close();
			return {};
		} catch (err:Dynamic) {
			return {error: err};
		}
	}
}
