import { filePath } from './mirror.mjs';

// The filesystem device supplies an absolute path within the mounted account
// home. Only the browser holds the file authority.
function relative(path, { root = false } = {}) {
  const normalized = filePath(path);
  if (!root && normalized === '/') throw new TypeError('Choose an entry inside the account home.');
  return normalized.slice(1);
}

function revision(value, { create = false } = {}) {
  if (create && value === null) return null;
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new TypeError('An exact saved file revision is required.');
  }
  return value;
}

export function createAccountHome({ files, valid, onChange = () => {} }) {
  const lifetime = new AbortController();
  function check() {
    lifetime.signal.throwIfAborted();
    if (!valid()) throw new DOMException('Account session changed.', 'AbortError');
  }

  async function request(callback) {
    check();
    const result = await callback();
    check();
    return result;
  }

  async function mutate(paths, callback) {
    const result = await request(callback);
    onChange(paths);
    return result;
  }

  return Object.freeze({
    list: (path = '/') => request(() => files.list(relative(path, { root: true }))),
    version: path => request(() => files.version(relative(path))),
    read: path => request(() => files.read(relative(path))),
    write(path, data, expected) {
      return mutate([path], () => files.write(
        relative(path), data, revision(expected, { create: true }), { signal: lifetime.signal },
      ));
    },
    mkdir(path) {
      return mutate([path], () => files.mkdir(relative(path)));
    },
    remove(path, expected) {
      return mutate([path], () => files.remove(relative(path), revision(expected)));
    },
    rmdir(path) {
      return mutate([path], () => files.remove(relative(path), null));
    },
    rename(source, destination, expected) {
      return mutate([source, destination], () => files.rename(
        relative(source), relative(destination), revision(expected),
      ));
    },
    close() {
      lifetime.abort(new DOMException('Account home unmounted.', 'AbortError'));
    },
  });
}
