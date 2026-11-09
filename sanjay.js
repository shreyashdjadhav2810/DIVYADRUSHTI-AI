 
document.addEventListener("DOMContentLoaded", function () {

    // Mobile Navigation
    const menuToggle = document.querySelector(".menu-toggle");
    const navLinks = document.querySelector(".nav-links");

    if (menuToggle && navLinks) {
        menuToggle.addEventListener("click", function () {
            navLinks.classList.toggle("active");
        });
    }

    // Navbar Scroll Effect
    const navbar = document.querySelector(".navbar");

    window.addEventListener("scroll", function () {
        if (navbar) {
            navbar.classList.toggle("scrolled", window.scrollY > 50);
        }
    });

    // Footer Year
    const footerYear = document.querySelector(".footer-year");

    if (footerYear) {
        footerYear.textContent = new Date().getFullYear();
    }

    // Krishna Voice - Home Page Only
    if (document.body.dataset.page !== "home") return;

    const krishnaAudio = new Audio("audio.mp3");
    krishnaAudio.preload = "auto";

    const voiceButton = document.getElementById("krishnaVoiceBtn");
    const voiceStatus = document.getElementById("krishnaVoiceStatus");

    function updateStatus(message) {
        if (voiceStatus) {
            voiceStatus.textContent = message;
        }
    }

    // Try autoplay when Home Page opens
    krishnaAudio.play()
        .then(function () {
            updateStatus("दिव्य संदेश सुरू आहे...");
        })
        .catch(function () {
            updateStatus("आवाज सुरू करण्यासाठी बटणावर क्लिक करा.");
        });

    // Play / Pause Button
    if (voiceButton) {
        voiceButton.addEventListener("click", function () {

            if (krishnaAudio.paused) {
                krishnaAudio.play()
                    .then(function () {
                        updateStatus("दिव्य संदेश सुरू आहे...");
                    })
                    .catch(function () {
                        updateStatus("आवाज सुरू होऊ शकला नाही. फाइल तपासा.");
                    });
            } else {
                krishnaAudio.pause();
                updateStatus("दिव्य संदेश थांबवला आहे.");
            }
        });
    }

    krishnaAudio.addEventListener("ended", function () {
        updateStatus("दिव्य संदेश पूर्ण झाला.");
    });

    krishnaAudio.addEventListener("error", function () {
        updateStatus("audio.mp3 फाइल सापडली नाही.");
    });

});
