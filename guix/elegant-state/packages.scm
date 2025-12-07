;;; elegant-state/packages.scm --- elegant-STATE package definitions
;;;
;;; This module defines the Guix packages for elegant-STATE.

(define-module (elegant-state packages)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix git-download)
  #:use-module (guix build-system cargo)
  #:use-module ((guix licenses) #:prefix license:)
  #:use-module (gnu packages crates-io)
  #:use-module (gnu packages crates-graphics)
  #:use-module (gnu packages crates-web)
  #:use-module (gnu packages pkg-config)
  #:use-module (gnu packages tls)
  ;; External tools
  #:use-module (gnu packages text)           ; pandoc
  #:use-module (gnu packages ocr)            ; tesseract
  #:use-module (gnu packages image))         ; leptonica (tesseract dep)

(define-public elegant-state
  (package
    (name "elegant-state")
    (version "0.2.0")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://github.com/Hyperpolymath/elegant-STATE")
             (commit (string-append "v" version))))
       (file-name (git-file-name name version))
       (sha256
        (base32 "0000000000000000000000000000000000000000000000000000"))))
    (build-system cargo-build-system)
    (arguments
     `(#:cargo-inputs
       (;; Database & Search
        ("rust-sled" ,rust-sled-0.34)
        ("rust-tantivy" ,rust-tantivy-0.22)
        ;; Fuzzy matching
        ("rust-fuzzy-matcher" ,rust-fuzzy-matcher-0.3)
        ("rust-nucleo-matcher" ,rust-nucleo-matcher-0.3)
        ;; Serialization
        ("rust-serde" ,rust-serde-1)
        ("rust-serde-json" ,rust-serde-json-1)
        ("rust-bincode" ,rust-bincode-1)
        ;; IDs & Time
        ("rust-ulid" ,rust-ulid-1)
        ("rust-chrono" ,rust-chrono-0.4)
        ;; GraphQL
        ("rust-async-graphql" ,rust-async-graphql-7)
        ("rust-async-graphql-axum" ,rust-async-graphql-axum-7)
        ;; Web server
        ("rust-axum" ,rust-axum-0.7)
        ("rust-tokio" ,rust-tokio-1)
        ("rust-tower" ,rust-tower-0.4)
        ("rust-tower-http" ,rust-tower-http-0.5)
        ;; CLI
        ("rust-clap" ,rust-clap-4)
        ;; Error handling
        ("rust-thiserror" ,rust-thiserror-1)
        ("rust-anyhow" ,rust-anyhow-1)
        ;; Logging
        ("rust-tracing" ,rust-tracing-0.1)
        ("rust-tracing-subscriber" ,rust-tracing-subscriber-0.3)
        ;; Utilities
        ("rust-dirs" ,rust-dirs-5)
        ;; Async streaming
        ("rust-async-stream" ,rust-async-stream-0.3)
        ("rust-futures-util" ,rust-futures-util-0.3))))
    (native-inputs
     (list pkg-config))
    (inputs
     (list openssl))
    ;; Propagated inputs are available at runtime for external tools
    (propagated-inputs
     (list pandoc          ; Document conversion
           tesseract-ocr)) ; OCR text extraction
    (home-page "https://github.com/Hyperpolymath/elegant-STATE")
    (synopsis "Local-first state graph for multi-agent orchestration")
    (description
     "elegant-STATE provides a persistent knowledge graph that multiple agents
(Claude, Llama, custom modules) can query and modify via GraphQL.

Features:
@itemize
@item Full-text search (tantivy)
@item Fuzzy/agrep matching
@item Document conversion (pandoc)
@item OCR text extraction (tesseract)
@item Multi-agent coordination (proposals, voting, reputation)
@item GraphQL subscriptions for real-time updates
@end itemize

Replaces manual state tracking (like STATE.adoc) with a queryable,
event-sourced graph database using sled for storage.")
    (license license:expat)))

;; Container definition for nerdctl/podman
(define-public elegant-state-container
  (package
    (inherit elegant-state)
    (name "elegant-state-container")
    (description
     "Container image for elegant-STATE with all tools included.

Use with:
@example
guix pack -f docker -S /bin=bin elegant-state-container
@end example

Or build a singularity image:
@example
guix pack -f squashfs elegant-state-container
@end example")))

;; Development variant with additional tools
(define-public elegant-state-dev
  (package
    (inherit elegant-state)
    (name "elegant-state-dev")
    (native-inputs
     (modify-inputs (package-native-inputs elegant-state)
       (prepend rust-clippy
                rust-rustfmt)))
    (synopsis "elegant-STATE with development tools")
    (description
     "Development version of elegant-STATE with clippy and rustfmt included.")))
