//! Interactive TUI dashboard. A clean two-pane "app in the terminal" front-end
//! over the same daemon the CLI uses.

use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::{
    Block, BorderType, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::DefaultTerminal;

use vaultcore::protocol::{Request, Response, StatusInfo};
use vaultcore::store::SecretMeta;

use crate::client;

const ACCENT: Color = Color::Cyan;
const REVEAL_SECS: u64 = 10;
const TOAST_SECS: u64 = 3;
const CLIP_CLEAR_SECS: u64 = 20;

#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    Normal,
    Search,
    Form,
    ConfirmDelete,
    Help,
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Field {
    Name,
    Tag,
    Value,
}

struct Form {
    editing: bool,
    name: String,
    tag: String,
    value: String,
    field: Field,
}

struct App {
    secrets: Vec<SecretMeta>,
    filtered: Vec<usize>,
    selected: usize,
    filter: String,
    mode: Mode,
    status: Option<StatusInfo>,
    conn_error: Option<String>,
    revealed: Option<String>,
    reveal_at: Option<Instant>,
    toast: Option<(String, Instant)>,
    form: Form,
    clip_clear_at: Option<Instant>,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        App {
            secrets: Vec::new(),
            filtered: Vec::new(),
            selected: 0,
            filter: String::new(),
            mode: Mode::Normal,
            status: None,
            conn_error: None,
            revealed: None,
            reveal_at: None,
            toast: None,
            form: Form {
                editing: false,
                name: String::new(),
                tag: String::new(),
                value: String::new(),
                field: Field::Name,
            },
            clip_clear_at: None,
            should_quit: false,
        }
    }

    fn req(&mut self, req: Request) -> Response {
        match client::request(&req) {
            Ok(resp) => resp,
            Err(e) => Response::Error {
                code: "daemon_unreachable".into(),
                message: e.to_string(),
            },
        }
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    fn refresh_status(&mut self) {
        match self.req(Request::Status) {
            Response::Status(s) => {
                self.status = Some(s);
                self.conn_error = None;
            }
            Response::Error { message, .. } => {
                self.status = None;
                self.conn_error = Some(message);
            }
            _ => {}
        }
    }

    fn refresh_list(&mut self) {
        match self.req(Request::List) {
            Response::List { secrets } => {
                self.secrets = secrets;
                self.recompute_filter();
            }
            Response::Error { message, .. } => self.toast(message),
            _ => {}
        }
    }

    fn refresh(&mut self) {
        self.refresh_status();
        self.refresh_list();
    }

    fn initialized(&self) -> bool {
        self.status.as_ref().map(|s| s.initialized).unwrap_or(false)
    }

    fn unlocked(&self) -> bool {
        self.status.as_ref().map(|s| s.unlocked).unwrap_or(false)
    }

    fn recompute_filter(&mut self) {
        let f = self.filter.to_lowercase();
        self.filtered = self
            .secrets
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                f.is_empty()
                    || s.name.to_lowercase().contains(&f)
                    || s.tag.to_lowercase().contains(&f)
            })
            .map(|(i, _)| i)
            .collect();
        if self.selected >= self.filtered.len() {
            self.selected = self.filtered.len().saturating_sub(1);
        }
        self.revealed = None;
        self.reveal_at = None;
    }

    fn current_meta(&self) -> Option<&SecretMeta> {
        self.filtered
            .get(self.selected)
            .and_then(|&i| self.secrets.get(i))
    }

    fn move_sel(&mut self, delta: i32) {
        if self.filtered.is_empty() {
            return;
        }
        let len = self.filtered.len() as i32;
        let mut idx = self.selected as i32 + delta;
        if idx < 0 {
            idx = 0;
        }
        if idx >= len {
            idx = len - 1;
        }
        if idx as usize != self.selected {
            self.selected = idx as usize;
            self.revealed = None;
            self.reveal_at = None;
        }
    }

    fn fetch_value(&mut self, name: String) -> Option<String> {
        let resp = self.req(Request::Get { name });
        self.refresh_status();
        match resp {
            Response::Secret { value } => Some(value),
            Response::Error { message, .. } => {
                self.toast(message);
                None
            }
            _ => None,
        }
    }

    fn toggle_reveal(&mut self) {
        if self.revealed.is_some() {
            self.revealed = None;
            self.reveal_at = None;
            return;
        }
        let Some(name) = self.current_meta().map(|m| m.name.clone()) else {
            return;
        };
        if let Some(v) = self.fetch_value(name) {
            self.revealed = Some(v);
            self.reveal_at = Some(Instant::now());
        }
    }

    fn copy_selected(&mut self) {
        let Some(name) = self.current_meta().map(|m| m.name.clone()) else {
            return;
        };
        if let Some(v) = self.fetch_value(name) {
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(v)) {
                Ok(_) => {
                    self.clip_clear_at =
                        Some(Instant::now() + Duration::from_secs(CLIP_CLEAR_SECS));
                    self.toast(format!("copied — clears in {CLIP_CLEAR_SECS}s"));
                }
                Err(e) => self.toast(format!("clipboard error: {e}")),
            }
        }
    }

    fn do_unlock(&mut self) {
        match self.req(Request::Unlock) {
            Response::Ok => {
                self.refresh();
                self.toast("unlocked");
            }
            Response::Error { message, .. } => self.toast(message),
            _ => {}
        }
    }

    fn do_lock(&mut self) {
        self.req(Request::Lock);
        self.revealed = None;
        self.reveal_at = None;
        self.refresh_status();
        self.toast("locked");
    }

    fn do_init(&mut self) {
        match self.req(Request::Init) {
            Response::Ok => {
                self.refresh();
                self.toast("vault initialized");
            }
            Response::Error { message, .. } => self.toast(message),
            _ => {}
        }
    }

    fn start_add(&mut self) {
        self.form = Form {
            editing: false,
            name: String::new(),
            tag: String::new(),
            value: String::new(),
            field: Field::Name,
        };
        self.mode = Mode::Form;
    }

    fn start_edit(&mut self) {
        let Some(meta) = self.current_meta() else {
            return;
        };
        self.form = Form {
            editing: true,
            name: meta.name.clone(),
            tag: meta.tag.clone(),
            value: String::new(),
            field: Field::Tag,
        };
        self.mode = Mode::Form;
    }

    fn submit_form(&mut self) {
        let f = &self.form;
        if f.name.trim().is_empty() {
            self.toast("name must not be empty");
            return;
        }
        let req = Request::Set {
            name: f.name.clone(),
            tag: f.tag.clone(),
            value: f.value.clone(),
            expires: None,
        };
        match self.req(req) {
            Response::Ok => {
                self.mode = Mode::Normal;
                self.refresh();
                self.toast("secret stored");
            }
            Response::Error { message, .. } => self.toast(message),
            _ => {}
        }
    }

    fn delete_selected(&mut self) {
        let Some(name) = self.current_meta().map(|m| m.name.clone()) else {
            self.mode = Mode::Normal;
            return;
        };
        match self.req(Request::Delete { name }) {
            Response::Ok => {
                self.mode = Mode::Normal;
                self.refresh();
                self.toast("secret deleted");
            }
            Response::Error { message, .. } => {
                self.mode = Mode::Normal;
                self.toast(message);
            }
            _ => self.mode = Mode::Normal,
        }
    }

    fn tick(&mut self) {
        let now = Instant::now();
        if let Some((_, t)) = self.toast {
            if now.duration_since(t) > Duration::from_secs(TOAST_SECS) {
                self.toast = None;
            }
        }
        if let Some(t) = self.reveal_at {
            if now.duration_since(t) > Duration::from_secs(REVEAL_SECS) {
                self.revealed = None;
                self.reveal_at = None;
            }
        }
        if let Some(t) = self.clip_clear_at {
            if now >= t {
                let _ = arboard::Clipboard::new().and_then(|mut c| c.set_text(String::new()));
                self.clip_clear_at = None;
            }
        }
    }
}

pub fn run() -> Result<()> {
    let mut terminal = ratatui::init();
    let mut app = App::new();
    app.refresh();
    let result = run_loop(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    let mut last_refresh = Instant::now();
    loop {
        terminal.draw(|f| ui(f, app))?;

        if event::poll(Duration::from_millis(400))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key);
                }
            }
        }

        app.tick();
        if last_refresh.elapsed() >= Duration::from_secs(1) {
            app.refresh_status();
            last_refresh = Instant::now();
        }
        if app.should_quit {
            break;
        }
    }
    Ok(())
}

// ---- input -------------------------------------------------------------

fn handle_key(app: &mut App, key: KeyEvent) {
    // Overlays first.
    match app.mode {
        Mode::Help => {
            app.mode = Mode::Normal;
            return;
        }
        Mode::ConfirmDelete => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => app.delete_selected(),
                _ => app.mode = Mode::Normal,
            }
            return;
        }
        Mode::Form => {
            handle_form_key(app, key);
            return;
        }
        Mode::Search => {
            handle_search_key(app, key);
            return;
        }
        Mode::Normal => {}
    }

    // Connection / init / locked gates.
    if app.conn_error.is_some() {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Char('r') => app.refresh(),
            _ => {}
        }
        return;
    }
    if !app.initialized() {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Char('i') | KeyCode::Enter => app.do_init(),
            _ => {}
        }
        return;
    }
    if !app.unlocked() {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Enter | KeyCode::Char('u') => app.do_unlock(),
            _ => {}
        }
        return;
    }

    // Unlocked dashboard.
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('j') | KeyCode::Down => app.move_sel(1),
        KeyCode::Char('k') | KeyCode::Up => app.move_sel(-1),
        KeyCode::Char('/') => app.mode = Mode::Search,
        KeyCode::Char('a') => app.start_add(),
        KeyCode::Char('e') => app.start_edit(),
        KeyCode::Char('d') => {
            if app.current_meta().is_some() {
                app.mode = Mode::ConfirmDelete;
            }
        }
        KeyCode::Char('r') | KeyCode::Enter => app.toggle_reveal(),
        KeyCode::Char('c') => app.copy_selected(),
        KeyCode::Char('L') => app.do_lock(),
        KeyCode::Char('?') => app.mode = Mode::Help,
        _ => {}
    }
}

fn handle_search_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc | KeyCode::Enter => app.mode = Mode::Normal,
        KeyCode::Backspace => {
            app.filter.pop();
            app.recompute_filter();
        }
        KeyCode::Down => app.move_sel(1),
        KeyCode::Up => app.move_sel(-1),
        KeyCode::Char(c) => {
            app.filter.push(c);
            app.recompute_filter();
        }
        _ => {}
    }
}

fn handle_form_key(app: &mut App, key: KeyEvent) {
    if key.code == KeyCode::Esc {
        app.mode = Mode::Normal;
        return;
    }
    // Ctrl+S submits from any field.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
        app.submit_form();
        return;
    }

    match key.code {
        KeyCode::Tab | KeyCode::Enter => {
            let advance = |f: Field| match f {
                Field::Name => Field::Tag,
                Field::Tag => Field::Value,
                Field::Value => Field::Value,
            };
            if app.form.field == Field::Value {
                app.submit_form();
            } else {
                // Skip the name field when editing (immutable).
                let next = advance(app.form.field);
                app.form.field = if app.form.editing && next == Field::Name {
                    Field::Tag
                } else {
                    next
                };
            }
        }
        KeyCode::Backspace => match app.form.field {
            Field::Name if !app.form.editing => {
                app.form.name.pop();
            }
            Field::Name => {}
            Field::Tag => {
                app.form.tag.pop();
            }
            Field::Value => {
                app.form.value.pop();
            }
        },
        KeyCode::Char(c) => match app.form.field {
            Field::Name if !app.form.editing => app.form.name.push(c),
            Field::Name => {}
            Field::Tag => app.form.tag.push(c),
            Field::Value => app.form.value.push(c),
        },
        _ => {}
    }
}

// ---- rendering ---------------------------------------------------------

fn ui(f: &mut Frame, app: &App) {
    let area = f.area();

    if app.conn_error.is_some() {
        draw_card(
            f,
            area,
            " Daemon unavailable ",
            &[
                Line::from(app.conn_error.clone().unwrap_or_default()),
                Line::from(""),
                Line::from("[r] retry    [q] quit"),
            ],
            Color::Red,
        );
        return;
    }
    if !app.initialized() {
        draw_card(
            f,
            area,
            " fnVault — not initialized ",
            &[
                Line::from("No vault found on this Mac."),
                Line::from(""),
                Line::from("Press [i] to create the master key and enroll Touch ID."),
                Line::from(""),
                Line::from("[i] init    [q] quit"),
            ],
            ACCENT,
        );
        draw_toast(f, area, app);
        return;
    }
    if !app.unlocked() {
        draw_card(
            f,
            area,
            " 🔒 fnVault — locked ",
            &[
                Line::from("The vault is locked."),
                Line::from(""),
                Line::from("Press [⏎] to unlock with Touch ID."),
                Line::from(""),
                Line::from("[⏎/u] unlock    [q] quit"),
            ],
            ACCENT,
        );
        draw_toast(f, area, app);
        return;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .split(area);

    draw_header(f, chunks[0], app);
    draw_search(f, chunks[1], app);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(chunks[2]);

    draw_list(f, body[0], app);
    draw_details(f, body[1], app);
    draw_footer(f, chunks[3], app);

    // Overlays.
    match app.mode {
        Mode::Form => draw_form(f, area, app),
        Mode::ConfirmDelete => draw_confirm(f, area, app),
        Mode::Help => draw_help(f, area),
        _ => {}
    }
    draw_toast(f, area, app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let right = match &app.status {
        Some(s) if s.unlocked => match s.idle_remaining_secs {
            Some(r) => format!("Unlocked · relock {}", fmt_secs(r)),
            None => "Unlocked".to_string(),
        },
        Some(_) => "Locked".to_string(),
        None => "…".to_string(),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Line::from(Span::styled(
            " fnVault ",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )))
        .title(Line::from(format!(" {right} ")).right_aligned());
    f.render_widget(block, area);
}

fn draw_search(f: &mut Frame, area: Rect, app: &App) {
    let active = app.mode == Mode::Search;
    let border = if active { ACCENT } else { Color::DarkGray };
    let shown = if app.filter.is_empty() && !active {
        Span::styled("type to filter…", Style::new().fg(Color::DarkGray))
    } else {
        Span::raw(app.filter.as_str())
    };
    let mut spans = vec![shown];
    if active {
        spans.push(Span::styled("▏", Style::new().fg(ACCENT)));
    }
    let p = Paragraph::new(Line::from(spans)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(border))
            .title(" Search "),
    );
    f.render_widget(p, area);
}

fn draw_list(f: &mut Frame, area: Rect, app: &App) {
    let items: Vec<ListItem> = app
        .filtered
        .iter()
        .filter_map(|&i| app.secrets.get(i))
        .map(|s| {
            let tag = if s.tag.is_empty() {
                Span::raw("")
            } else {
                Span::styled(
                    format!("  {}", s.tag),
                    Style::new().fg(if is_sensitive(&s.tag) {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }),
                )
            };
            ListItem::new(Line::from(vec![Span::raw(s.name.clone()), tag]))
        })
        .collect();

    let title = format!(" Secrets ({}) ", app.filtered.len());
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(title),
        )
        .highlight_style(
            Style::new()
                .fg(Color::Black)
                .bg(ACCENT)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▸ ");

    let mut state = ListState::default();
    if !app.filtered.is_empty() {
        state.select(Some(app.selected));
    }
    f.render_stateful_widget(list, area, &mut state);
}

fn draw_details(f: &mut Frame, area: Rect, app: &App) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .title(" Details ");

    let lines: Vec<Line> = match app.current_meta() {
        None => vec![Line::from(Span::styled(
            "No secret selected.",
            Style::new().fg(Color::DarkGray),
        ))],
        Some(meta) => {
            let value_line = match &app.revealed {
                Some(v) => Line::from(vec![
                    label("Value"),
                    Span::styled(v.clone(), Style::new().fg(Color::Green)),
                ]),
                None => Line::from(vec![
                    label("Value"),
                    Span::styled("••••••••••••", Style::new().fg(Color::DarkGray)),
                    Span::styled("   [r] reveal", Style::new().fg(Color::DarkGray)),
                ]),
            };
            vec![
                Line::from(vec![label("Name"), Span::raw(meta.name.clone())]),
                Line::from(vec![
                    label("Tag"),
                    Span::raw(if meta.tag.is_empty() {
                        "—".to_string()
                    } else {
                        meta.tag.clone()
                    }),
                ]),
                Line::from(vec![label("Created"), Span::raw(meta.created.clone())]),
                Line::from(vec![label("Updated"), Span::raw(meta.updated.clone())]),
                Line::from(vec![
                    label("Expires"),
                    match &meta.expires {
                        Some(e) => Span::raw(e.clone()),
                        None => Span::styled("—", Style::new().fg(Color::DarkGray)),
                    },
                ]),
                Line::from(""),
                value_line,
                Line::from(""),
                Line::from(Span::styled(
                    "[r] reveal   [c] copy   [e] edit   [d] delete",
                    Style::new().fg(Color::DarkGray),
                )),
            ]
        }
    };

    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let hint = match app.mode {
        Mode::Search => "type to filter   ⏎/Esc done   ↑↓ move",
        _ => "↑↓ move   / search   a add   e edit   r reveal   c copy   d delete   L lock   ? help   q quit",
    };
    f.render_widget(
        Paragraph::new(Span::styled(hint, Style::new().fg(Color::DarkGray))),
        area,
    );
}

fn draw_form(f: &mut Frame, area: Rect, app: &App) {
    let rect = centered_rect(60, 11, area);
    f.render_widget(Clear, rect);

    let title = if app.form.editing {
        " Edit secret "
    } else {
        " Add secret "
    };
    let field_line = |name: &str, val: &str, focused: bool, masked: bool, disabled: bool| {
        let shown = if masked && !val.is_empty() {
            "•".repeat(val.chars().count())
        } else {
            val.to_string()
        };
        let mut spans = vec![Span::styled(
            format!("{name:<7}"),
            Style::new().fg(if disabled {
                Color::DarkGray
            } else {
                Color::Gray
            }),
        )];
        let mut val_style = Style::new();
        if focused {
            val_style = val_style.fg(ACCENT).add_modifier(Modifier::BOLD);
        }
        spans.push(Span::styled(shown, val_style));
        if focused {
            spans.push(Span::styled("▏", Style::new().fg(ACCENT)));
        }
        Line::from(spans)
    };

    let lines = vec![
        Line::from(""),
        field_line(
            "Name",
            &app.form.name,
            app.form.field == Field::Name,
            false,
            app.form.editing,
        ),
        field_line(
            "Tag",
            &app.form.tag,
            app.form.field == Field::Tag,
            false,
            false,
        ),
        field_line(
            "Value",
            &app.form.value,
            app.form.field == Field::Value,
            true,
            false,
        ),
        Line::from(""),
        Line::from(Span::styled(
            "⇥/⏎ next field   ⏎ on Value or ^S submit   Esc cancel",
            Style::new().fg(Color::DarkGray),
        )),
    ];

    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(ACCENT))
                .title(title),
        ),
        rect,
    );
}

fn draw_confirm(f: &mut Frame, area: Rect, app: &App) {
    let name = app
        .current_meta()
        .map(|m| m.name.clone())
        .unwrap_or_default();
    let rect = centered_rect(50, 7, area);
    f.render_widget(Clear, rect);
    let lines = vec![
        Line::from(""),
        Line::from(format!("Delete `{name}`?")),
        Line::from(""),
        Line::from(Span::styled(
            "[y] yes    [n] no",
            Style::new().fg(Color::DarkGray),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines).alignment(Alignment::Center).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(Color::Red))
                .title(" Confirm delete "),
        ),
        rect,
    );
}

fn draw_help(f: &mut Frame, area: Rect) {
    let rect = centered_rect(50, 16, area);
    f.render_widget(Clear, rect);
    let keys = [
        ("↑↓ / j k", "move selection"),
        ("/", "search / filter"),
        ("⏎ / r", "reveal / hide value"),
        ("c", "copy value to clipboard"),
        ("a", "add a secret"),
        ("e", "edit selected secret"),
        ("d", "delete selected secret"),
        ("L", "lock the vault now"),
        ("?", "this help"),
        ("q / Esc", "quit"),
    ];
    let mut lines = vec![Line::from("")];
    for (k, d) in keys {
        lines.push(Line::from(vec![
            Span::styled(format!("  {k:<12}"), Style::new().fg(ACCENT)),
            Span::raw(d),
        ]));
    }
    f.render_widget(
        Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(ACCENT))
                .title(" Help "),
        ),
        rect,
    );
}

fn draw_card(f: &mut Frame, area: Rect, title: &str, lines: &[Line], color: Color) {
    let rect = centered_rect(60, (lines.len() as u16) + 4, area);
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(lines.to_vec())
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(color))
                    .title(title.to_string()),
            ),
        rect,
    );
}

fn draw_toast(f: &mut Frame, area: Rect, app: &App) {
    let Some((msg, _)) = &app.toast else {
        return;
    };
    let w = (msg.len() as u16 + 4).min(area.width.saturating_sub(2));
    let rect = Rect {
        x: area.x + area.width.saturating_sub(w + 1),
        y: area.y + area.height.saturating_sub(2),
        width: w,
        height: 1,
    };
    f.render_widget(Clear, rect);
    f.render_widget(
        Paragraph::new(Span::styled(
            format!(" {msg} "),
            Style::new().fg(Color::Black).bg(ACCENT),
        )),
        rect,
    );
}

fn label(name: &str) -> Span<'static> {
    Span::styled(format!("{name:<9}"), Style::new().fg(Color::DarkGray))
}

fn is_sensitive(tag: &str) -> bool {
    let t = tag.to_lowercase();
    ["banking", "prod", "production", "bank"]
        .iter()
        .any(|k| t.contains(k))
}

fn fmt_secs(secs: u64) -> String {
    format!("{:02}:{:02}", secs / 60, secs % 60)
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}
