use iced::widget::{button, column, container, progress_bar, row, text, text_input};
use iced::{Element, Event, Length, Task, Theme};
use std::path::PathBuf;

// Bring in your existing manager so the GUI can actually encrypt/decrypt
use cryption::manager::CryptionManager;

pub fn run_app() -> iced::Result {
    iced::application(CryptionApp::new, CryptionApp::update, CryptionApp::view)
        .title("Cryption - Desktop Vault")
        .theme(|_: &CryptionApp| Theme::Dark)
        .subscription(|_: &CryptionApp| iced::event::listen().map(Message::WindowEvents))
        .run()
}

// 1. The State of our App
#[derive(Default)]
struct CryptionApp {
    dropped_file: Option<PathBuf>,
    password: String,
    password_strength: f32, // Ranges from 0.0 to 4.0
    status_message: Option<String>, // NEW: To show success/error feedback
}

// 2. The Messages (Events) our App handles
#[derive(Debug, Clone)]
enum Message {
    PasswordChanged(String),
    FileDropped(PathBuf),
    WindowEvents(Event),
    EncryptClicked, // NEW
    DecryptClicked, // NEW
}

impl CryptionApp {
    fn new() -> (Self, Task<Message>) {
        (Self::default(), Task::none())
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            // Handle Password & Strength Meter Logic
            Message::PasswordChanged(pw) => {
                self.password = pw;
                self.password_strength = calculate_strength(&self.password);
                self.status_message = None; // Clear status on typing
                Task::none()
            }
            // Handle Drag & Drop Logic
            Message::FileDropped(path) => {
                self.dropped_file = Some(path);
                self.status_message = None; // Clear status on new file
                Task::none()
            }
            // Listen for native OS window events
            Message::WindowEvents(event) => {
                if let Event::Window(iced::window::Event::FileDropped(path)) = event {
                    return Task::perform(async { path }, Message::FileDropped);
                }
                Task::none()
            }
            // --- NEW: Handle Encryption Logic ---
            Message::EncryptClicked => {
                if let Some(path) = &self.dropped_file {
                    if self.password.is_empty() {
                        self.status_message = Some("❌ Passkey cannot be empty.".into());
                        return Task::none();
                    }

                    let input_path = path.to_string_lossy().to_string();
                    let output_path = format!("{}.cryp", input_path);

                    match CryptionManager::encrypt_file(&input_path, &output_path, &self.password) {
                        Ok(_) => self.status_message = Some(format!("✅ Encrypted successfully:\n{}", output_path)),
                        Err(e) => self.status_message = Some(format!("❌ Error: {}", e)),
                    }
                } else {
                    self.status_message = Some("⚠️ Please drop a file first.".into());
                }
                Task::none()
            }
            // --- NEW: Handle Decryption Logic ---
            Message::DecryptClicked => {
                if let Some(path) = &self.dropped_file {
                    if self.password.is_empty() {
                        self.status_message = Some("❌ Passkey cannot be empty.".into());
                        return Task::none();
                    }

                    let input_path = path.to_string_lossy().to_string();
                    
                    // Simple logic to name the decrypted file
                    let output_path = if input_path.ends_with(".cryp") {
                        input_path.trim_end_matches(".cryp").to_string()
                    } else {
                        format!("{}.decrypted", input_path)
                    };

                    match CryptionManager::decrypt_file(&input_path, &output_path, &self.password) {
                        Ok(_) => self.status_message = Some(format!("🔓 Decrypted successfully:\n{}", output_path)),
                        Err(e) => self.status_message = Some(format!("❌ Error: {}", e)),
                    }
                } else {
                    self.status_message = Some("⚠️ Please drop a file first.".into());
                }
                Task::none()
            }
        }
    }

    // 3. The Layout and UI
    fn view(&self) -> Element<'_, Message> {
        // --- DRAG AND DROP ZONE ---
        let drop_text = match &self.dropped_file {
            Some(path) => format!("📁 Selected:\n{}", path.display()),
            None => String::from("⬇️ Drag & Drop a File Here"),
        };

        let drop_zone = container(
            text(drop_text)
                .align_x(iced::alignment::Horizontal::Center)
        )
        .width(Length::Fill)
        .height(Length::Fixed(150.0)) // Slightly reduced to fit the buttons
        .center_x(Length::Fill)
        .center_y(Length::Fill)
        .style(container::rounded_box);

        // --- PASSWORD INPUT ---
        let pw_input = text_input("Enter Passkey...", &self.password)
            .on_input(Message::PasswordChanged)
            .secure(true) // Obscures the text
            .padding(10);

        // --- STRENGTH METER ---
        let meter_label = text("Password Strength:");
        let meter = progress_bar(0.0..=4.0, self.password_strength)
            .style(move |_theme: &Theme| get_meter_style(_theme, self.password_strength));

        // --- NEW: ACTION BUTTONS ---
        let encrypt_btn = button(
            text("🔒 Encrypt").align_x(iced::alignment::Horizontal::Center)
        )
        .width(Length::Fill)
        .padding(15)
        .on_press(Message::EncryptClicked)
        .style(button::primary);

        let decrypt_btn = button(
            text("🔓 Decrypt").align_x(iced::alignment::Horizontal::Center)
        )
        .width(Length::Fill)
        .padding(15)
        .on_press(Message::DecryptClicked)
        .style(button::secondary);

        let action_row = row![encrypt_btn, decrypt_btn].spacing(15);

        // --- NEW: STATUS MESSAGE ---
        let status_text = match &self.status_message {
            Some(msg) => text(msg).size(14),
            None => text("Ready.").size(14),
        };

        // --- MAIN LAYOUT ---
        let content = column![
            drop_zone,
            text("Passkey Setup").size(20),
            pw_input,
            meter_label,
            meter,
            action_row,
            container(status_text).center_x(Length::Fill).width(Length::Fill)
        ]
        .spacing(20)
        .padding(40)
        .max_width(500);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x(Length::Fill)
            .center_y(Length::Fill)
            .into()
    }
}

// --- HELPER FUNCTIONS ---

/// A simple algorithm to visualize password strength
fn calculate_strength(pw: &str) -> f32 {
    let mut score = 0.0;
    if pw.len() >= 8 { score += 1.0; }
    if pw.chars().any(|c| c.is_uppercase()) { score += 1.0; }
    if pw.chars().any(|c| c.is_numeric()) { score += 1.0; }
    if pw.chars().any(|c| !c.is_alphanumeric()) { score += 1.0; }
    score
}

/// Changes the color of the progress bar based on the score
fn get_meter_style(_theme: &Theme, score: f32) -> progress_bar::Style {
    let color = if score <= 1.0 {
        iced::Color::from_rgb(0.8, 0.2, 0.2) // Red
    } else if score <= 3.0 {
        iced::Color::from_rgb(1.0, 0.75, 0.0) // Yellow/Orange
    } else {
        iced::Color::from_rgb(0.2, 0.6, 0.2) // Green
    };

    progress_bar::Style {
        background: iced::Background::Color(iced::Color::from_rgb(0.2, 0.2, 0.2)),
        bar: iced::Background::Color(color),
        border: iced::Border {
            radius: 2.0.into(),
            ..Default::default()
        },
    }
}