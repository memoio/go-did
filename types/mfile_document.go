package types

type MfileDIDDocument struct {
	Context    string    `json:"context"`
	ID         MfileDID  `json:"id"`
	Type       string    `json:"type"`
	Encode     string    `json:"encode"`
	Price      int64     `json:"price"`
	Controller MemoDID   `json:"controller"`
	Keywords   []string  `json:"keywords"`
	Read       []MemoDID `json:"read,omitempty"`
}
