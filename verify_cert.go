package main

import (
	"fmt"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"github.com/emmansun/gmsm/smx509"
)

func verifyCert(_ fyne.Window) {
	w := appWin.NewWindow("verifyCert")
	size := fyne.Size{Width: 500, Height: 150}

	setIcon(w)

	w.Resize(size)
	w.CenterOnScreen()
	w.Show()

	var userCert, chainCert string
	//
	var certChainBtn *widget.Button
	certChainBtn = widget.NewButton("证书链", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}

			defer reader.Close()

			chainCert = reader.URI().Path()
			certChainBtn.SetText(chainCert)
		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".pem", ".p7b"}))
		fd.Show()
	})

	var userCertBtn *widget.Button
	userCertBtn = widget.NewButton("用户证书", func() {
		fd := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if reader == nil {
				return
			}

			defer reader.Close()
			userCert = reader.URI().Path()
			userCertBtn.SetText(userCert)

		}, w)
		fd.SetFilter(storage.NewExtensionFileFilter([]string{".pem", ".der"}))
		fd.Show()
	})

	//
	var check *widget.Button
	check = widget.NewButton("验证", func() {

		check.Disable()
		defer check.Enable()

		if userCert == "" || chainCert == "" {
			dialog.ShowError(fmt.Errorf("缺少用户证书或证书链"), w)
		}
		vp := verifyCertParam{
			userCertFile:  userCert,
			chainCertFile: chainCert,
			w:             w,
			result:        make([]string, 0),
		}
		if err := vp.verifyCertFinal(); err != nil {
			dialog.ShowError(err, w)
		}
	})

	v3 := container.NewVBox(userCertBtn, certChainBtn, check)
	v3Center := container.NewCenter(v3)

	content := container.NewVBox(v3Center)
	w.SetContent(content)
}

type verifyCertParam struct {
	userCertFile, chainCertFile string
	w                           fyne.Window
	result                      []string
}

func (param *verifyCertParam) verifyCertFinal() error {
	chainCert, err := os.ReadFile(param.chainCertFile)
	if err != nil {
		return err
	}

	pool := smx509.NewCertPool()
	chain, err := parseChain(strings.Split(param.chainCertFile, ".")[1], chainCert)
	if err != nil {
		return err
	}
	for _, c := range chain {
		pool.AddCert(c)
	}

	user, err := os.ReadFile(param.userCertFile)
	if err != nil {
		return err
	}

	u, err := parseCert(user)
	if err != nil {
		return err
	}

	_, err = u.Verify(smx509.VerifyOptions{Roots: pool})
	if err != nil {
		dialog.ShowInformation("警告", err.Error(), param.w)
	}

	if len(chain) > 2 {
		return fmt.Errorf("暂不支持3级及以上证书链验证")
	}
	if len(chain) == 2 {
		if chain[0].Issuer.CommonName == chain[0].Subject.CommonName {
			t := chain[0]
			chain[0] = chain[1]
			chain[1] = t
		}
	}

	param.verifyPartialChain(u, chain)
	dialog.ShowInformation("验签结果", strings.Join(param.result, "\r\n"), param.w)
	return nil
}

func (param *verifyCertParam) verifyPartialChain(cert *smx509.Certificate, parents []*smx509.Certificate) {
	if len(parents) == 0 {
		return
	}

	stage1 := fmt.Sprintf("Verifing %s by %s: ", cert.Subject.CommonName,
		parents[0].Subject.CommonName)

	err := cert.CheckSignatureFrom(parents[0])
	if err != nil {
		param.result = append(param.result,
			stage1+fmt.Sprintf("certificate signature from parent is invalid: %v", err))
		return
	}
	stage3 := "OK"
	param.result = append(param.result, stage1+stage3)
	if len(parents) == 1 {
		// there is no more parent to check, return
		return
	}
	param.verifyPartialChain(parents[0], parents[1:])
}
