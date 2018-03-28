const SegfaultHandler = require('segfault-handler');
const NodeHookAddon = require('bindings')('node-iohook');

/**
 * mapping of module event type to the event string
 *
 * @type {Object}
 */
const eventMap = {
  3: 'keypress',
  4: 'keydown',
  5: 'keyup',
  6: 'mouseclick',
  7: 'mousedown',
  8: 'mouseup',
  9: 'mousemove',
  10: 'mousedrag',
  11: 'mousewheel',
};

/** Class to handle hook callbacks */
class IOCallback {
  constructor() {
    this.callbacks = [];
    this.active = false;
  }

  add(event, callback) {
    /**
     * Adds a callback to the respective event
     *
     * @param {String} event the event string
     * @param {Function} callback the callback function
     */
    if (!this.callbacks[event]) {
      this.callbacks[event] = [];
    }

    this.callbacks[event].push(callback);
  }

  clearCallback() {
    /**
     * Clears all callbacks
     *
     * @param {String} Event the event string
     */
    this.callbacks = [];
  }

  run() {
    /**
     * Setup the callbacks when IOHook recieves an event.
     *
     * @param {Object} msg the hook object
     *
     * @return {Function} callback function
     */
    return (msg) => {
      if (this.active === false || msg === false) return;

      this.runCallbacks(eventMap[msg.type], msg);
    };
  }

  runCallbacks(event, msg) {
    /**
     * Calls every callback attached to an event
     *
     * @param {String} event the event string
     * @param {Object} msg the hook object
     */
    if (this.callbacks[event]) {
      this.callbacks[event].forEach(callback => callback(msg));
    }
  }
}

class IOHook {
  constructor() {
    this.callback = new IOCallback();
    this.callbacks = {};

    this.started = false;

    SegfaultHandler.registerHandler('crash.log');
  }

  static getStatus() {
    return NodeHookAddon.getStatus();
  }

  /**
   * Creates a callback to an event string
   *
   * @param {String} event event string to hook
   * @param {Function} callback callback function
   */
  on(event, callback) {
    this.callback.add(event, callback);
  }

  /**
   * Starts the hook module
   *
   * @param {Function} callback optional callback
   */
  start(callback) {
    if (this.started === false) {
      NodeHookAddon.startHook(this.callback.run(callback));

      this.started = true;
      this.callback.active = true;
    } else {
      console.error('IOHook has already started');
    }
  }

  /**
   * Pauses all callbacks
   */
  pause() {
    this.callback.active = false;
  }

  /**
   * Resumes all callbacks
   */
  resume() {
    this.callback.active = true;
  }

  /**
   * Stops the callback module
   */
  stop() {
    if (this.started === true) {
      this.started = false;
      NodeHookAddon.stopHook();

      this.callback.active = false;
      this.callback.clearCallback();
    } else {
      console.error('IOHook has not yet started');
    }
  }
}

module.exports = IOHook;
