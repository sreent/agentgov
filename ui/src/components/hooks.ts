import { useState, type Dispatch, type SetStateAction } from 'react';

/**
 * State that starts as `value` and can be changed on the page, and starts again from it when
 * `dep` changes: by default `value` itself; give the page's data when `value` is made anew
 * each time it is drawn ({ ...from the data }).
 */
export function useSynced<T>(value: T, dep: unknown = value): [T, Dispatch<SetStateAction<T>>] {
  const [state, setState] = useState(value);
  const [prev, setPrev] = useState(dep);
  if (prev !== dep) {
    setPrev(dep);
    setState(value);
  }
  return [state, setState];
}
