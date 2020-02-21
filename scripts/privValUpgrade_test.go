package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/privval"
)

const lastSignBytes = "6C080211085100000000000022480A2023A8C65085F5833939B6A8EC2DB" +
	"2993E8756B3A376ECB63DDC97452CC286B81112240A2016CE70F9C99C0A" +
	"46EBBED94D0D4C55AC47A2CA9C8046C05965B987FE8D70AEFB10012A0C0" +
	"8C3F8BCF20510D8F7C1EB013207746573744E6574"

const oldPrivvalContent = `{
  "address": "0591BD05426263A248A464C1CDA891AF4013A577",
  "pub_key": {
    "type": "tendermint/PubKeySm2",
    "value": "AV0eSinoYv2baEJiuJJ0oJ33Eha0kISwsoqgWQC+iBpm"
  },
  "last_height": "5",
  "last_round": "0",
  "last_step": 3,
  "last_signature": "Q7/cItTcsOY3eupv7s53cxOpXHeaWg8ARsDmj9FCYU36xEQ/wnlQA25AB0GNtww5CGrIEwPQcvrUj8oTMps1NA==",
  "last_signbytes": "` + lastSignBytes + `",
  "priv_key": {
    "type": "tendermint/PrivKeySm2",
    "value": "9yeVNqq98dXbiy33hp8ZUGTwRl8ubp3HMqyeybUUxs0="
  }
}`

func TestLoadAndUpgrade(t *testing.T) {

	oldFilePath := initTmpOldFile(t)
	defer os.Remove(oldFilePath)
	newStateFile, err := ioutil.TempFile("", "priv_validator_state*.json")
	defer os.Remove(newStateFile.Name())
	require.NoError(t, err)
	newKeyFile, err := ioutil.TempFile("", "priv_validator_key*.json")
	defer os.Remove(newKeyFile.Name())
	require.NoError(t, err)
	emptyOldFile, err := ioutil.TempFile("", "priv_validator_empty*.json")
	require.NoError(t, err)
	defer os.Remove(emptyOldFile.Name())

	type args struct {
		oldPVPath      string
		newPVKeyPath   string
		newPVStatePath string
	}
	tests := []struct {
		name      string
		args      args
		wantErr   bool
		wantPanic bool
	}{
		{"successful upgrade",
			args{oldPVPath: oldFilePath, newPVKeyPath: newKeyFile.Name(), newPVStatePath: newStateFile.Name()},
			false, false,
		},
		{"unsuccessful upgrade: empty old privval file",
			args{oldPVPath: emptyOldFile.Name(), newPVKeyPath: newKeyFile.Name(), newPVStatePath: newStateFile.Name()},
			true, false,
		},
		{"unsuccessful upgrade: invalid new paths (1/3)",
			args{oldPVPath: oldFilePath, newPVKeyPath: "", newPVStatePath: newStateFile.Name()},
			false, true,
		},
		{"unsuccessful upgrade: invalid new paths (2/3)",
			args{oldPVPath: oldFilePath, newPVKeyPath: newKeyFile.Name(), newPVStatePath: ""},
			false, true,
		},
		{"unsuccessful upgrade: invalid new paths (3/3)",
			args{oldPVPath: oldFilePath, newPVKeyPath: "", newPVStatePath: ""},
			false, true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// need to re-write the file everytime because upgrading renames it
			err := ioutil.WriteFile(oldFilePath, []byte(oldPrivvalContent), 0600)
			require.NoError(t, err)
			if tt.wantPanic {
				require.Panics(t, func() { loadAndUpgrade(tt.args.oldPVPath, tt.args.newPVKeyPath, tt.args.newPVStatePath) })
			} else {
				err = loadAndUpgrade(tt.args.oldPVPath, tt.args.newPVKeyPath, tt.args.newPVStatePath)
				if tt.wantErr {
					assert.Error(t, err)
					fmt.Println("ERR", err)
				} else {
					assert.NoError(t, err)
					upgradedPV := privval.LoadFilePV(tt.args.newPVKeyPath, tt.args.newPVStatePath)
					oldPV, err := privval.LoadOldFilePV(tt.args.oldPVPath + ".bak")
					require.NoError(t, err)

					assert.Equal(t, oldPV.Address, upgradedPV.Key.Address)
					assert.Equal(t, oldPV.Address, upgradedPV.GetAddress())
					assert.Equal(t, oldPV.PubKey, upgradedPV.Key.PubKey)
					assert.Equal(t, oldPV.PubKey, upgradedPV.GetPubKey())
					assert.Equal(t, oldPV.PrivKey, upgradedPV.Key.PrivKey)

					assert.Equal(t, oldPV.LastHeight, upgradedPV.LastSignState.Height)
					assert.Equal(t, oldPV.LastRound, upgradedPV.LastSignState.Round)
					assert.Equal(t, oldPV.LastSignature, upgradedPV.LastSignState.Signature)
					assert.Equal(t, oldPV.LastSignBytes, upgradedPV.LastSignState.SignBytes)
					assert.Equal(t, oldPV.LastStep, upgradedPV.LastSignState.Step)

				}
			}
		})
	}
}

func initTmpOldFile(t *testing.T) string {
	tmpfile, err := ioutil.TempFile("", "priv_validator_*.json")
	require.NoError(t, err)
	t.Logf("created test file %s", tmpfile.Name())
	_, err = tmpfile.WriteString(oldPrivvalContent)
	require.NoError(t, err)

	return tmpfile.Name()
}
