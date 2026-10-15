// Modal dialogs: a question, or a form. ask() resolves to the form's values (or what its
// submit resolves to), or null when it is cancelled.

import { useEffect, useRef, useState, useSyncExternalStore, type FormEvent, type ReactNode } from 'react';
import { cx } from '../lib/format';
import { Icon } from './Icon';

export type Values = Record<string, any>;
type Dyn<T> = T | ((values: Values) => T);

/** A field: text (the default), textarea, code (a monospace textarea), select, checkbox or number. */
export interface Field {
  id: string;
  label: Dyn<string>;
  type?: 'text' | 'textarea' | 'code' | 'select' | 'checkbox' | 'number';
  value?: unknown;
  required?: boolean;
  placeholder?: Dyn<string | undefined>;
  hint?: Dyn<ReactNode>;
  rows?: number;
  mono?: boolean;
  min?: number;
  /** Suggestions as it is typed. */
  datalist?: string[];
  /** Offer to load a local file of this type (".rego") into it. */
  file?: string;
  options?: { value: string; label: string }[];
  /** It must be typed exactly so (a name, to confirm deleting it). */
  match?: string;
  mismatch?: string;
  /** Hidden while the form's values say so; a hidden field isn't checked. */
  hidden?: (values: Values) => boolean;
}
export interface Section { type: 'section'; label: string; id?: string; hidden?: (values: Values) => boolean }
/** Two fields side by side. */
export interface Row { type: 'row'; fields: (Field | null | false | undefined)[] }
export type FieldSpec = Field | Section | Row | null | false | undefined;

export interface DialogContext {
  values: Values;
  /** Change some fields' values. */
  set: (changes: Values) => void;
}

export interface AskOptions<R> {
  title: string;
  text?: ReactNode;
  tone?: 'primary' | 'danger';
  iconName?: string;
  confirm?: string;
  /** null: no way to cancel (a message to acknowledge). */
  cancel?: string | null;
  fields?: FieldSpec[];
  /** Shown above the fields. */
  extra?: ReactNode | ((ctx: DialogContext) => ReactNode);
  /** Shown below them. */
  after?: ReactNode | ((ctx: DialogContext) => ReactNode);
  wide?: boolean;
  /**
   * With submit, the dialog stays open while it runs: an error it throws (a refused API call,
   * say) shows in the dialog so nothing typed is lost, and the dialog resolves to its result
   * once it succeeds.
   */
  submit?: (values: Values) => R | Promise<R>;
  busy?: string;
  /** When a field changes: new values for others (to keep one in step with another). */
  onChange?: (values: Values, changed: string) => Values | void;
}

interface Request {
  id: number;
  opts: AskOptions<any>;
  resolve: (value: any) => void;
  opener: Element | null;
}

let current: Request | null = null;
let nextId = 0;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

function finish(req: Request, value: unknown) {
  if (current !== req) return;
  current = null;
  emit();
  req.resolve(value);
}

export function ask<R = Values>(opts: AskOptions<R>): Promise<R | null> {
  return new Promise((resolve) => {
    if (current) finish(current, null);
    current = { id: ++nextId, opts, resolve, opener: document.activeElement };
    emit();
  });
}

/** Close the dialog open, as if cancelled (signing out, say). */
export function closeDialog(): void {
  if (current) finish(current, null);
}

const isField = (f: FieldSpec): f is Field => Boolean(f) && (f as Field).id !== undefined && (f as Section).type !== 'section';

function inputFields(fields: FieldSpec[]): Field[] {
  return fields.flatMap((f) => {
    if (!f) return [];
    if (f.type === 'row') return (f as Row).fields.filter(isField);
    if (f.type === 'section') return [];
    return [f as Field];
  });
}

const dyn = <T,>(value: Dyn<T>, values: Values): T => (typeof value === 'function' ? (value as (v: Values) => T)(values) : value);

function initialValues(fields: FieldSpec[]): Values {
  const values: Values = {};
  for (const f of inputFields(fields)) {
    if (f.type === 'checkbox') values[f.id] = Boolean(f.value);
    else if (f.type === 'select') {
      const want = f.value == null ? '' : String(f.value);
      const options = f.options || [];
      values[f.id] = options.some((o) => o.value === want) ? want : (options[0]?.value ?? '');
    } else values[f.id] = f.value == null ? '' : String(f.value);
  }
  return values;
}

export function DialogHost() {
  const req = useSyncExternalStore((l) => {
    listeners.add(l);
    return () => listeners.delete(l);
  }, () => current);
  return req ? <DialogView key={req.id} req={req} /> : null;
}

function DialogView({ req }: { req: Request }) {
  const { opts } = req;
  const fields = (opts.fields || []).filter(Boolean) as FieldSpec[];
  const ref = useRef<HTMLDialogElement>(null);
  const form = useRef<HTMLFormElement>(null);
  const [values, setValues] = useState(() => initialValues(fields));
  const [error, setError] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const confirm = opts.confirm ?? 'Confirm';
  const cancel = opts.cancel === undefined ? 'Cancel' : opts.cancel;
  const tone = opts.tone ?? 'primary';

  useEffect(() => {
    const dlg = ref.current!;
    if (!dlg.open) dlg.showModal();
    const first = [...form.current!.querySelectorAll<HTMLElement>('input:not([type="file"]), textarea, select')]
      .find((el) => !el.closest('[hidden]'));
    (first || form.current!.querySelector<HTMLElement>('button[type="submit"]'))?.focus();
    return () => {
      if (dlg.open) dlg.close();
      // Back to the control that opened it, if it is still there.
      const opener = req.opener as HTMLElement | null;
      if (opener?.isConnected) opener.focus();
    };
  }, [req]);

  const set = (changes: Values) => setValues((v) => ({ ...v, ...changes }));
  const change = (id: string, value: unknown) => {
    setValues((v) => {
      const next = { ...v, [id]: value };
      const more = opts.onChange?.(next, id);
      return more ? { ...next, ...more } : next;
    });
  };
  const ctx: DialogContext = { values, set };
  const hiddenField = (f: Field) => Boolean(f.hidden?.(values));
  const focusField = (id: string) => form.current?.querySelector<HTMLElement>(`#dlg-${CSS.escape(id)}`)?.focus();

  const onSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (working) return;
    const out: Values = {};
    for (const f of inputFields(fields)) {
      if (f.type === 'checkbox') {
        out[f.id] = Boolean(values[f.id]);
        continue;
      }
      const raw = String(values[f.id] ?? '');
      const value = f.type === 'code' ? raw : raw.trim();
      if (!hiddenField(f)) {
        const label = dyn(f.label, values);
        if (f.required && !value.trim()) {
          setError(`${label} is required.`);
          focusField(f.id);
          return;
        }
        if (f.match != null && value !== f.match) {
          setError(f.mismatch || `${label} doesn't match.`);
          focusField(f.id);
          return;
        }
      }
      out[f.id] = value;
    }
    if (!opts.submit) {
      finish(req, out);
      return;
    }
    setWorking(true);
    setError(null);
    try {
      const result = await opts.submit(out);
      finish(req, result ?? out);
    } catch (err: any) {
      setWorking(false);
      setError(err?.message || String(err));
    }
  };

  const renderField = (f: FieldSpec, key: number | string): ReactNode => {
    if (!f) return null;
    if (f.type === 'section') {
      const s = f as Section;
      return <h3 key={key} className="dialog-section" id={s.id ? `dlg-${s.id}` : undefined} hidden={s.hidden?.(values)}>{s.label}</h3>;
    }
    if (f.type === 'row') {
      return <div key={key} className="form-row">{(f as Row).fields.map((x, i) => renderField(x, i))}</div>;
    }
    return <FieldView key={f.id} f={f as Field} values={values} change={change} />;
  };

  return (
    <dialog
      ref={ref}
      className={cx('dialog', opts.wide && 'dialog--wide')}
      aria-labelledby="dialog-title"
      data-tone={tone === 'danger' ? 'critical' : 'accent'}
      onCancel={(e) => {
        if (working) e.preventDefault();
      }}
      onClose={() => finish(req, null)}
    >
      <form ref={form} className="dialog-form" noValidate onSubmit={onSubmit}>
        <div className="dialog-head">
          <Icon name={opts.iconName ?? 'info'} />
          <div className="stack" style={{ gap: 6 }}>
            <h2 id="dialog-title" className="dialog-title">{opts.title}</h2>
            {opts.text ? <p className="dialog-text">{opts.text}</p> : null}
          </div>
        </div>
        {typeof opts.extra === 'function' ? opts.extra(ctx) : opts.extra ?? null}
        {fields.map((f, i) => renderField(f, i))}
        {typeof opts.after === 'function' ? opts.after(ctx) : opts.after ?? null}
        <p className="form-error" role="alert" hidden={!error}>{error}</p>
        <div className="dialog-actions">
          {cancel ? <button type="button" className="btn" disabled={working} onClick={() => finish(req, null)}>{cancel}</button> : null}
          <button type="submit" className={`btn btn--${tone}`} disabled={working}>{working ? (opts.busy ?? 'Saving…') : confirm}</button>
        </div>
      </form>
    </dialog>
  );
}

function FieldView({ f, values, change }: { f: Field; values: Values; change: (id: string, value: unknown) => void }) {
  const id = `dlg-${f.id}`;
  const picker = useRef<HTMLInputElement>(null);
  const area = useRef<HTMLTextAreaElement>(null);
  const hint = f.hint !== undefined ? dyn(f.hint, values) : null;
  const hintEl = hint ? <p className="hint" id={`${id}-hint`}>{hint}</p> : null;
  const describedBy = hint ? `${id}-hint` : undefined;
  const label = dyn(f.label, values);
  const hidden = Boolean(f.hidden?.(values));
  const placeholder = f.placeholder !== undefined ? dyn(f.placeholder, values) : undefined;
  if (f.type === 'checkbox') {
    return (
      <div className="field" hidden={hidden}>
        <label className="check" htmlFor={id}>
          <input id={id} name={f.id} type="checkbox" checked={Boolean(values[f.id])} aria-describedby={describedBy}
            onChange={(e) => change(f.id, e.target.checked)} />
          {label}
        </label>
        {hintEl}
      </div>
    );
  }
  const value = String(values[f.id] ?? '');
  let control: ReactNode;
  let loader: ReactNode = null;
  if (f.type === 'textarea' || f.type === 'code') {
    control = (
      <textarea ref={area} id={id} name={f.id} rows={f.rows || 3} placeholder={placeholder || undefined}
        className={f.type === 'code' ? 'code-input' : undefined} spellCheck={f.type === 'code' ? false : undefined}
        aria-describedby={describedBy} value={value} onChange={(e) => change(f.id, e.target.value)} />
    );
    if (f.file) {
      // Read a local file into the editor; nothing is uploaded until the form is saved.
      loader = (
        <div className="btn-row">
          <input ref={picker} type="file" accept={f.file} hidden onChange={async (e) => {
            const file = e.target.files?.[0];
            if (file) change(f.id, await file.text());
            e.target.value = '';
            area.current?.focus();
          }} />
          <button type="button" className="btn btn--sm" onClick={() => picker.current?.click()}>
            <Icon name="upload" />{`Load a ${f.file} file`}
          </button>
        </div>
      );
    }
  } else if (f.type === 'select') {
    control = (
      <select id={id} name={f.id} aria-describedby={describedBy} value={value} onChange={(e) => change(f.id, e.target.value)}>
        {(f.options || []).map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    );
  } else {
    control = (
      <input id={id} name={f.id} type={f.type === 'number' ? 'number' : 'text'} autoComplete="off"
        placeholder={placeholder || undefined} min={f.min} step={f.type === 'number' ? 1 : undefined}
        list={f.datalist ? `${id}-list` : undefined} spellCheck={f.mono ? false : undefined}
        className={f.mono ? 'mono' : undefined} aria-describedby={describedBy}
        value={value} onChange={(e) => change(f.id, e.target.value)} />
    );
  }
  return (
    <div className="field" hidden={hidden}>
      <label htmlFor={id}>{label}{f.required ? null : <span className="muted"> (optional)</span>}</label>
      {control}
      {f.datalist ? <datalist id={`${id}-list`}>{f.datalist.map((v) => <option key={v} value={v} />)}</datalist> : null}
      {loader}
      {hintEl}
    </div>
  );
}
