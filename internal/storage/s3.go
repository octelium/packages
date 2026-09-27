package storage

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type S3 struct {
	client *s3.Client
	bucket string
}

func openR2(bucket string) (*S3, error) {
	account := os.Getenv("R2_ACCOUNT_ID")
	id := os.Getenv("R2_ACCESS_KEY_ID")
	secret := os.Getenv("R2_SECRET_ACCESS_KEY")
	if account == "" || id == "" || secret == "" {
		return nil, fmt.Errorf("R2_ACCOUNT_ID, R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY are required")
	}
	client := s3.New(s3.Options{
		Region:                     "auto",
		BaseEndpoint:               aws.String("https://" + account + ".r2.cloudflarestorage.com"),
		Credentials:                credentials.NewStaticCredentialsProvider(id, secret, ""),
		UsePathStyle:               true,
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
		ResponseChecksumValidation: aws.ResponseChecksumValidationWhenRequired,
	})
	return &S3{client: client, bucket: bucket}, nil
}

func openS3(ctx context.Context, bucket string) (*S3, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, err
	}
	return &S3{client: s3.NewFromConfig(cfg), bucket: bucket}, nil
}

func (s *S3) List(ctx context.Context, prefix string) ([]Object, error) {
	var objects []Object
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			objects = append(objects, Object{
				Key:      aws.ToString(o.Key),
				Size:     aws.ToInt64(o.Size),
				ETag:     strings.Trim(aws.ToString(o.ETag), `"`),
				Modified: aws.ToTime(o.LastModified),
			})
		}
	}
	return objects, nil
}

func (s *S3) Get(ctx context.Context, key, dst string) error {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return ErrNotExist
		}
		return err
	}
	defer out.Body.Close()
	return writeFile(dst, out.Body)
}

func (s *S3) Put(ctx context.Context, key, src, contentType, cacheControl string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	h := md5.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return err
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.bucket),
		Key:           aws.String(key),
		Body:          f,
		ContentLength: aws.Int64(size),
		ContentMD5:    aws.String(base64.StdEncoding.EncodeToString(h.Sum(nil))),
		ContentType:   aws.String(contentType),
		CacheControl:  aws.String(cacheControl),
	})
	return err
}

func (s *S3) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	return err
}
