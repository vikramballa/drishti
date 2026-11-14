import { useEffect, useState } from 'preact/hooks';

export interface Async<T> { data: T | null; error: string | null; loading: boolean }

/** Run a promise-returning loader when deps change; ignores stale results. */
export function useAsync<T>(fn: () => Promise<T> | null, deps: unknown[]): Async<T> {
  const [s, set] = useState<Async<T>>({ data: null, error: null, loading: true });
  useEffect(() => {
    let alive = true;
    const p = fn();
    if (!p) { set({ data: null, error: null, loading: false }); return; }
    set((o) => ({ data: o.data, error: null, loading: true }));
    p.then((data) => alive && set({ data, error: null, loading: false }), (e: Error) => alive && set({ data: null, error: e.message, loading: false }));
    return () => { alive = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return s;
}

export function useDebounced<T>(v: T, ms = 200): T {
  const [d, setD] = useState(v);
  useEffect(() => { const t = setTimeout(() => setD(v), ms); return () => clearTimeout(t); }, [v, ms]);
  return d;
}
