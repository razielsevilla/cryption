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
    processing_progress: Option<f32>, // P3-03: Tracks current file progress (0.0 to 1.0)
}

// 2. The Messages (Events) our App handles
#[derive(Debug, Clone)]
enum Message {
    PasswordChanged(String),
    FileDropped(PathBuf),
    WindowEvents(Event),
    EncryptClicked, // NEW
    DecryptClicked, // NEW
    ProgressUpdated(f32), // P3-03: Update for the progress bar
    OperationFinished(Result<String, String>), // P3-03: Final result
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
                    let password = self.password.clone();
                    
                    // Get file size for percentage calculation
                    let file_size = std::fs::metadata(&input_path).map(|m| m.len()).unwrap_or(1);

                    self.processing_progress = Some(0.0);
                    self.status_message = Some("🔒 Encrypting...".into());

                    return Task::stream(iced::stream::channel(10, move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
                        use iced::futures::SinkExt;
                        let (tx, rx) = std::sync::mpsc::channel();
                        
                        std::thread::spawn(move || {
                            let res = CryptionManager::encrypt_file(&input_path, &output_path, &password, Some(|bytes| {
                                let _ = tx.send(Message::ProgressUpdated(bytes as f32 / file_size as f32));
                            }));

                            let final_msg = match res {
                                Ok(_) => Message::OperationFinished(Ok(output_path)),
                                Err(e) => Message::OperationFinished(Err(e.to_string())),
                            };
                            let _ = tx.send(final_msg);
                        });

                        while let Ok(msg) = rx.recv() {
                            let _ = output.send(msg).await;
                        }
                    }));
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
                    let out_path = if input_path.ends_with(".cryp") {
                        input_path.trim_end_matches(".cryp").to_string()
                    } else {
                        format!("{}.decrypted", input_path)
                    };
                    let password = self.password.clone();
                    
                    // Decryption size calculation
                    let file_size = std::fs::metadata(&input_path).map(|m| m.len()).unwrap_or(66);
                    let payload_size = file_size.saturating_sub(34 + 32);

                    self.processing_progress = Some(0.0);
                    self.status_message = Some("🔓 Decrypting...".into());

                    return Task::stream(iced::stream::channel(10, move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
                        use iced::futures::SinkExt;
                        let (tx, rx) = std::sync::mpsc::channel();
                        
                        std::thread::spawn(move || {
                            let res = CryptionManager::decrypt_file(&input_path, &out_path, &password, Some(|bytes| {
                                let progress = if payload_size > 0 { bytes as f32 / payload_size as f32 } else { 1.0 };
                                let _ = tx.send(Message::ProgressUpdated(progress));
                            }));

                            let final_msg = match res {
                                Ok(_) => Message::OperationFinished(Ok(out_path)),
                                Err(e) => Message::OperationFinished(Err(e.to_string())),
                            };
                            let _ = tx.send(final_msg);
                        });

                        while let Ok(msg) = rx.recv() {
                            let _ = output.send(msg).await;
                        }
                    }));
                } else {
                    self.status_message = Some("⚠️ Please drop a file first.".into());
                }
                Task::none()
            }
            // --- Progress & Completion Handlers ---
            Message::ProgressUpdated(p) => {
                self.processing_progress = Some(p.clamp(0.0, 1.0));
                Task::none()
            }
            Message::OperationFinished(result) => {
                self.processing_progress = None;
                match result {
                    Ok(path) => self.status_message = Some(format!("✅ Success:\n{}", path)),
                    Err(err) => self.status_message = Some(format!("❌ Error: {}", err)),
                }
                Task::none()
            }
        }
    }

    // 3. The Layout and UI
    fn view(&self) -> Element<'_, Message> {
        let is_processing = self.processing_progress.is_some();

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
        let mut pw_input = text_input("Enter Passkey...", &self.password)
            .on_input(Message::PasswordChanged)
            .secure(true) // Obscures the text
            .padding(10);
            
        if is_processing {
            // Disable input while processing
            pw_input = pw_input.on_input(|_| Message::WindowEvents(Event::Window(iced::window::Event::Focused))); // Dummy action
        }

        // --- STRENGTH METER ---
        let meter_label = text("Password Strength:");
        let meter = progress_bar(0.0..=4.0, self.password_strength)
            .style(move |_theme: &Theme| get_meter_style(_theme, self.password_strength));

        // --- NEW: ACTION BUTTONS ---
        let mut encrypt_btn = button(
            text("🔒 Encrypt").align_x(iced::alignment::Horizontal::Center)
        )
        .width(Length::Fill)
        .padding(15)
        .style(button::primary);

        let mut decrypt_btn = button(
            text("🔓 Decrypt").align_x(iced::alignment::Horizontal::Center)
        )
        .width(Length::Fill)
        .padding(15)
        .style(button::secondary);

        if !is_processing {
            encrypt_btn = encrypt_btn.on_press(Message::EncryptClicked);
            decrypt_btn = decrypt_btn.on_press(Message::DecryptClicked);
        }

        let action_row = row![encrypt_btn, decrypt_btn].spacing(15);

        // --- NEW: STATUS MESSAGE ---
        let status_text = match &self.status_message {
            Some(msg) => text(msg).size(14).align_x(iced::alignment::Horizontal::Center),
            None => text("Ready.").size(14).align_x(iced::alignment::Horizontal::Center),
        };

        // --- NEW: FILE PROCESSING PROGRESS ---
        let progress_view = if let Some(progress) = self.processing_progress {
            column![
                text(format!("Processing... {:.0}%", progress * 100.0))
                    .size(14)
                    .align_x(iced::alignment::Horizontal::Center),
                progress_bar(0.0..=1.0, progress)
            ].spacing(5).width(Length::Fill)
        } else {
            column![].width(Length::Fill)
        };

        // --- MAIN LAYOUT ---
        let content = column![
            drop_zone,
            text("Passkey Setup").size(20),
            pw_input,
            meter_label,
            meter,
            action_row,
            progress_view,
            container(status_text).width(Length::Fill)
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