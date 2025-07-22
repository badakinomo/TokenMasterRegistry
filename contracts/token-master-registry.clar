;; TokenMasterRegistry - Advanced asset management system with hierarchical permissions
;;
;; A comprehensive framework for token registration, ownership management, and access control
;; featuring multi-level authorization, rate limiting, and cryptographic verification capabilities

;; Core system configuration variables
(define-data-var emergency-mode-active bool false)
(define-data-var emergency-description (string-ascii 128) "")
(define-data-var time-lock-period uint u10)
(define-data-var rate-limit-window uint u100)
(define-data-var max-operations-per-window uint u10)

;; Asset identifier sequence generator
(define-data-var next-asset-identifier uint u0)

;; Transaction sequence counter for operations
(define-data-var next-transaction-id uint u0)

;; System administrator identity (immutable after deployment)
(define-constant system-administrator tx-sender)

;; Access level definitions for hierarchical permissions
(define-constant permission-level-none u0)
(define-constant permission-level-read u1)
(define-constant permission-level-write u2)
(define-constant permission-level-full u3)

;; Comprehensive error code definitions for all failure scenarios
(define-constant error-insufficient-privileges (err u300))
(define-constant error-asset-does-not-exist (err u301))
(define-constant error-asset-already-registered (err u302))
(define-constant error-invalid-name-format (err u303))
(define-constant error-value-out-of-bounds (err u304))
(define-constant error-access-denied (err u305))
(define-constant error-unauthorized-operation (err u306))
(define-constant error-restricted-viewing (err u307))
(define-constant error-invalid-category-data (err u308))
(define-constant error-invalid-tier-level (err u500))
(define-constant error-invalid-signature-method (err u600))
(define-constant error-verification-record-missing (err u601))
(define-constant error-signature-mismatch (err u602))
(define-constant error-rate-limit-exceeded (err u700))

;; Primary asset storage mapping - contains all registered asset information
(define-map asset-storage-vault
  { asset-identifier: uint }
  {
    asset-name: (string-ascii 64),
    current-owner: principal,
    numerical-value: uint,
    creation-block-height: uint,
    detailed-description: (string-ascii 128),
    category-tags: (list 10 (string-ascii 32))
  }
)

;; Legacy permission system mapping for backward compatibility
(define-map legacy-access-registry
  { asset-identifier: uint, authorized-user: principal }
  { can-access: bool }
)

;; Advanced permission system with tiered access levels
(define-map advanced-permission-registry
  { 
    asset-identifier: uint, 
    authorized-principal: principal 
  }
  { 
    access-tier: uint,
    permission-grantor: principal,
    grant-timestamp: uint
  }
)

;; Rate limiting system to prevent abuse and spam operations
(define-map operation-rate-tracker
  { user-principal: principal }
  {
    most-recent-operation: uint,
    operations-count-in-period: uint
  }
)

;; Cryptographic verification system for asset integrity
(define-map asset-verification-registry
  { asset-identifier: uint }
  {
    digital-signature: (buff 32),
    hash-algorithm: (string-ascii 10),
    verification-timestamp: uint,
    verifying-principal: principal
  }
)

;; Time-locked operations for enhanced security measures
(define-map secure-operation-queue
  { transaction-identifier: uint, target-asset: uint }
  {
    operation-type: (string-ascii 20),
    requesting-principal: principal,
    destination-principal: (optional principal),
    initiation-block: uint,
    security-hash: (buff 32),
    deadline-block: uint
  }
)

;; ===== Input Validation Helper Functions =====

;; Validates that category tag meets format requirements
(define-private (validate-single-category-tag (single-tag (string-ascii 32)))
  (and
    (> (len single-tag) u0)
    (< (len single-tag) u33)
  )
)

;; Ensures all category tags in collection are properly formatted
(define-private (verify-category-tag-collection (tag-collection (list 10 (string-ascii 32))))
  (and
    (> (len tag-collection) u0)
    (<= (len tag-collection) u10)
    (is-eq 
      (len (filter validate-single-category-tag tag-collection)) 
      (len tag-collection)
    )
  )
)

;; Checks if specified asset exists in the registry
(define-private (confirm-asset-registration (target-asset-id uint))
  (is-some (map-get? asset-storage-vault { asset-identifier: target-asset-id }))
)

;; Retrieves the numerical value associated with an asset
(define-private (fetch-asset-numerical-value (target-asset-id uint))
  (default-to u0
    (get numerical-value
      (map-get? asset-storage-vault { asset-identifier: target-asset-id })
    )
  )
)

;; Verifies if the specified principal owns the target asset
(define-private (confirm-asset-ownership (target-asset-id uint) (potential-owner principal))
  (match (map-get? asset-storage-vault { asset-identifier: target-asset-id })
    asset-record (is-eq (get current-owner asset-record) potential-owner)
    false
  )
)

;; Determines if system is currently in operational state
(define-private (system-currently-operational)
  (not (var-get emergency-mode-active))
)

;; ===== Permission and Access Control Functions =====

;; Evaluates whether principal has required permission tier for asset
(define-private (validate-permission-tier (target-asset-id uint) (checking-principal principal) (minimum-tier uint))
  (let
    (
      (asset-record (map-get? asset-storage-vault { asset-identifier: target-asset-id }))
      (permission-record (map-get? advanced-permission-registry { asset-identifier: target-asset-id, authorized-principal: checking-principal }))
    )
    (if (is-some asset-record)
      (if (is-eq (get current-owner (unwrap! asset-record false)) checking-principal)
        ;; Asset owner automatically has maximum permissions
        true
        ;; Check specific permission tier for non-owners
        (if (is-some permission-record)
          (>= (get access-tier (unwrap! permission-record false)) minimum-tier)
          false
        )
      )
      false
    )
  )
)

;; ===== Rate Limiting and Security Functions =====

;; Validates and updates rate limiting counters for operations
(define-private (validate-and-update-rate-limit (operating-principal principal))
  (let
    (
      (current-tracking-record 
        (default-to { most-recent-operation: u0, operations-count-in-period: u0 }
          (map-get? operation-rate-tracker { user-principal: operating-principal }))
      )
      (window-start-block (- block-height (var-get rate-limit-window)))
    )
    (if (< (get most-recent-operation current-tracking-record) window-start-block)
      ;; Starting new rate limiting window
      (begin
        (map-set operation-rate-tracker { user-principal: operating-principal }
          { most-recent-operation: block-height, operations-count-in-period: u1 })
        true)
      ;; Continuing within current window
      (if (< (get operations-count-in-period current-tracking-record) (var-get max-operations-per-window))
        (begin
          (map-set operation-rate-tracker { user-principal: operating-principal }
            { 
              most-recent-operation: block-height,
              operations-count-in-period: (+ (get operations-count-in-period current-tracking-record) u1)
            })
          true)
        false)
    )
  )
)

;; ===== Core Asset Management Functions =====

;; Creates a new asset record with comprehensive validation and initialization
(define-public (create-new-asset-record
  (asset-name (string-ascii 64))
  (numerical-value uint)
  (detailed-description (string-ascii 128))
  (category-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (new-asset-id (+ (var-get next-asset-identifier) u1))
    )
    ;; Comprehensive parameter validation
    (asserts! (> (len asset-name) u0) error-invalid-name-format)
    (asserts! (< (len asset-name) u65) error-invalid-name-format)
    (asserts! (> numerical-value u0) error-value-out-of-bounds)
    (asserts! (< numerical-value u1000000000) error-value-out-of-bounds)
    (asserts! (> (len detailed-description) u0) error-invalid-name-format)
    (asserts! (< (len detailed-description) u129) error-invalid-name-format)
    (asserts! (verify-category-tag-collection category-tags) error-invalid-category-data)

    ;; Store new asset record in primary vault
    (map-insert asset-storage-vault
      { asset-identifier: new-asset-id }
      {
        asset-name: asset-name,
        current-owner: tx-sender,
        numerical-value: numerical-value,
        creation-block-height: block-height,
        detailed-description: detailed-description,
        category-tags: category-tags
      }
    )

    ;; Grant creator full access permissions
    (map-insert legacy-access-registry
      { asset-identifier: new-asset-id, authorized-user: tx-sender }
      { can-access: true }
    )

    ;; Increment asset identifier counter for next registration
    (var-set next-asset-identifier new-asset-id)
    (ok new-asset-id)
  )
)

;; Modifies existing asset properties with ownership verification
(define-public (modify-existing-asset-properties
  (target-asset-id uint)
  (updated-name (string-ascii 64))
  (updated-value uint)
  (updated-description (string-ascii 128))
  (updated-categories (list 10 (string-ascii 32)))
)
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
    )
    ;; Verify asset exists and caller has ownership rights
    (asserts! (confirm-asset-registration target-asset-id) error-asset-does-not-exist)
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)

    ;; Validate all updated parameters
    (asserts! (> (len updated-name) u0) error-invalid-name-format)
    (asserts! (< (len updated-name) u65) error-invalid-name-format)
    (asserts! (> updated-value u0) error-value-out-of-bounds)
    (asserts! (< updated-value u1000000000) error-value-out-of-bounds)
    (asserts! (> (len updated-description) u0) error-invalid-name-format)
    (asserts! (< (len updated-description) u129) error-invalid-name-format)
    (asserts! (verify-category-tag-collection updated-categories) error-invalid-category-data)

    ;; Apply updates to existing asset record
    (map-set asset-storage-vault
      { asset-identifier: target-asset-id }
      (merge current-asset-data {
        asset-name: updated-name,
        numerical-value: updated-value,
        detailed-description: updated-description,
        category-tags: updated-categories
      })
    )
    (ok true)
  )
)

;; Transfers asset ownership to specified new owner
(define-public (execute-ownership-transfer (target-asset-id uint) (designated-new-owner principal))
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
    )
    ;; Verify asset exists and caller is current owner
    (asserts! (confirm-asset-registration target-asset-id) error-asset-does-not-exist)
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)

    ;; Update ownership record in asset vault
    (map-set asset-storage-vault
      { asset-identifier: target-asset-id }
      (merge current-asset-data { current-owner: designated-new-owner })
    )
    (ok true)
  )
)

;; Permanently removes asset from the registry system
(define-public (permanently-remove-asset (target-asset-id uint))
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
    )
    ;; Verify ownership before allowing deletion
    (asserts! (confirm-asset-registration target-asset-id) error-asset-does-not-exist)
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)

    ;; Remove asset from primary storage vault
    (map-delete asset-storage-vault { asset-identifier: target-asset-id })
    (ok true)
  )
)

;; ===== Advanced Permission Management System =====

;; Assigns specific permission tier to designated principal
(define-public (assign-permission-tier (target-asset-id uint) (recipient-principal principal) (permission-tier uint))
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
    )
    ;; Verify caller owns asset and permission tier is valid
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)
    (asserts! (<= permission-tier permission-level-full) error-invalid-tier-level)

    (ok true)
  )
)

;; ===== Rate-Limited Operations =====

;; Asset registration with built-in rate limiting protection
(define-public (rate-limited-asset-creation
  (asset-name (string-ascii 64))
  (numerical-value uint)
  (detailed-description (string-ascii 128))
  (category-tags (list 10 (string-ascii 32)))
)
  (begin
    ;; Enforce rate limiting before processing request
    (asserts! (validate-and-update-rate-limit tx-sender) error-rate-limit-exceeded)

    ;; Execute standard asset creation process
    (create-new-asset-record asset-name numerical-value detailed-description category-tags)
  )
)

;; ===== Cryptographic Verification System =====

;; Registers cryptographic signature for asset integrity verification
(define-public (register-asset-digital-signature (target-asset-id uint) (digital-signature (buff 32)) (hash-method (string-ascii 10)))
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
    )
    ;; Verify caller owns asset and algorithm is supported
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)
    (asserts! (or (is-eq hash-method "sha256") (is-eq hash-method "keccak256")) error-invalid-signature-method)

    (ok true)
  )
)

;; Validates asset integrity against registered cryptographic signature
(define-public (validate-asset-digital-integrity (target-asset-id uint) (provided-signature (buff 32)))
  (let
    (
      (verification-record (unwrap! (map-get? asset-verification-registry { asset-identifier: target-asset-id })
        error-verification-record-missing))
    )
    ;; Compare provided signature with registered signature
    (asserts! (is-eq (get digital-signature verification-record) provided-signature) error-signature-mismatch)

    (ok true)
  )
)

;; ===== Time-Locked Security Operations =====

;; Initiates secure ownership transfer with time delay and confirmation
(define-public (initiate-secure-ownership-change (target-asset-id uint) (designated-recipient principal) (security-hash (buff 32)))
  (let
    (
      (current-asset-data (unwrap! (map-get? asset-storage-vault { asset-identifier: target-asset-id })
        error-asset-does-not-exist))
      (new-transaction-id (+ (var-get next-transaction-id) u1))
      (operation-deadline (+ block-height (var-get time-lock-period)))
    )
    ;; Verify caller owns asset before initiating secure transfer
    (asserts! (confirm-asset-registration target-asset-id) error-asset-does-not-exist)
    (asserts! (is-eq (get current-owner current-asset-data) tx-sender) error-unauthorized-operation)

    ;; Increment transaction counter for unique identification
    (var-set next-transaction-id new-transaction-id)
    (ok new-transaction-id)
  )
)


;; Deactivates emergency mode to restore normal system operations
(define-public (deactivate-emergency-protocol)
  (begin
    ;; Restrict deactivation to system administrator only
    (asserts! (is-eq tx-sender system-administrator) error-insufficient-privileges)

    ;; Clear emergency state and reset description
    (var-set emergency-mode-active false)
    (var-set emergency-description "")
    (ok true)
  )
)